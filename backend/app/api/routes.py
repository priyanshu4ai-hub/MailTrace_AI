from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from email.utils import getaddresses
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.models.schemas import InvestigationResponse, PhishingScanRequest, PhishingScanResponse
from app.services.ai_engine import ThreatAnalyzerService
from app.services.auth_verifier import AuthVerifier
from app.services.geo_osint import GeoTrackerService
from app.services.parser import EMLParser, InvalidEmailError
from app.services.phishing_detector import PhishingDetector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["investigation"])

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml", ".txt"}


@router.post("/phishing/analyze", response_model=PhishingScanResponse)
def analyze_phishing(payload: PhishingScanRequest) -> PhishingScanResponse:
    """Analyze untrusted URLs and message text locally without opening any link."""

    assessment = PhishingDetector().analyze(
        urls=[payload.url, *payload.urls],
        message=payload.text,
        sender=payload.sender,
        reply_to=payload.reply_to,
        authentication=payload.authentication.model_dump(),
    )
    return PhishingScanResponse.model_validate(assessment)


@router.post("/investigate", response_model=InvestigationResponse)
async def investigate_email(
    file: Annotated[UploadFile, File(description="An .eml or .txt email file, up to 5 MB")],
) -> InvestigationResponse:
    filename = file.filename or ""
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml and .txt files are accepted.",
        )

    try:
        uploaded_bytes = await file.read(MAX_FILE_SIZE_BYTES + 1)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file could not be read.",
        ) from exc

    if not uploaded_bytes:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="The uploaded email file is empty.",
        )
    if len(uploaded_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="The uploaded file exceeds the 5 MB limit.",
        )

    await file.seek(0)

    try:
        email_data = await EMLParser().parse_upload(file)
        authentication = AuthVerifier().verify(email_data["authentication_results"])
        phishing_assessment = PhishingDetector().analyze(
            urls=email_data.get("urls", []),
            message="\n".join((email_data.get("subject", ""), email_data.get("body", ""))),
            sender=email_data.get("from", ""),
            reply_to=email_data.get("reply_to", ""),
            authentication=authentication,
            link_mismatches=email_data.get("link_mismatches", []),
        )

        geo_hops, threat_analysis = await asyncio.gather(
            GeoTrackerService().track_hops(email_data["received_headers"]),
            ThreatAnalyzerService().analyze(
                email_data,
                authentication,
                deterministic_assessment=phishing_assessment,
            ),
        )

        payload: dict[str, Any] = {
            "email": email_data,
            "authentication": authentication,
            "geo_hops": geo_hops,
            "threat_analysis": threat_analysis,
            "attack_graph": _build_attack_graph(
                email_data=email_data,
                authentication=authentication,
                geo_hops=geo_hops,
                threat_analysis=threat_analysis,
            ),
        }
        canonical_payload = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        payload["evidence_hash"] = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        return InvestigationResponse.model_validate(payload)
    except InvalidEmailError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Email investigation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to investigate the uploaded email.",
        ) from exc


def _build_attack_graph(
    email_data: dict[str, Any],
    authentication: dict[str, str],
    geo_hops: list[dict[str, str]],
    threat_analysis: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    message_id = email_data.get("message_id") or "uploaded-email"
    email_node_id = f"email:{message_id}"
    nodes: list[dict[str, Any]] = [
        {
            "id": email_node_id,
            "name": email_data.get("subject") or "Email message",
            "type": "email",
        }
    ]
    links: list[dict[str, Any]] = []

    sender = _first_address(email_data.get("from", ""))
    if sender:
        sender_id = f"sender:{sender.lower()}"
        nodes.append({"id": sender_id, "name": sender, "type": "sender"})
        links.append({"source": sender_id, "target": email_node_id, "relation": "SENT"})

    for recipient in _addresses(email_data.get("to", "")):
        recipient_id = f"recipient:{recipient.lower()}"
        nodes.append({"id": recipient_id, "name": recipient, "type": "recipient"})
        links.append({"source": email_node_id, "target": recipient_id, "relation": "DELIVERED_TO"})

    for hop in geo_hops:
        ip = hop["ip"]
        location = ", ".join(
            value for value in (hop.get("city"), hop.get("country")) if value and value != "Unknown"
        )
        nodes.append(
            {
                "id": f"ip:{ip}",
                "name": f"{ip} ({location})" if location else ip,
                "type": "relay_ip",
                "country": hop.get("country", "Unknown"),
                "city": hop.get("city", "Unknown"),
                "isp": hop.get("isp", "Unknown"),
                "asn": hop.get("asn", "Unknown"),
            }
        )
        links.append({"source": f"ip:{ip}", "target": email_node_id, "relation": "RELAYED"})

    auth_id = "authentication:results"
    auth_name = " | ".join(
        f"{mechanism.upper()}: {'pass' if passed else 'fail'}"
        for mechanism, passed in authentication.items()
    )
    nodes.append({"id": auth_id, "name": auth_name, "type": "authentication"})
    links.append({"source": auth_id, "target": email_node_id, "relation": "VALIDATES"})

    threat_id = "threat:assessment"
    nodes.append(
        {
            "id": threat_id,
            "name": threat_analysis.get("classification", "Unknown"),
            "type": "threat_assessment",
            "confidence_score": threat_analysis.get("confidence_score", 0),
        }
    )
    links.append({"source": threat_id, "target": email_node_id, "relation": "ASSESSES"})

    return {"nodes": nodes, "links": links}


def _addresses(header_value: str) -> list[str]:
    addresses = [address for _, address in getaddresses([header_value]) if address]
    return list(dict.fromkeys(addresses))


def _first_address(header_value: str) -> str:
    addresses = _addresses(header_value)
    return addresses[0] if addresses else header_value.strip()
