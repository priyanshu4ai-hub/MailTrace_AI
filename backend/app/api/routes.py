from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from email.utils import getaddresses
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.db.models import Case
from app.db.session import get_db
from app.models.schemas import (
    AnalystNoteCreate,
    AnalystNoteResponse,
    CaseCreate,
    CaseResponse,
    CaseUpdate,
    InvestigationResponse,
    PhishingScanRequest,
    PhishingScanResponse,
    TimelineSummaryResponse,
)
from app.services import case_service
from app.services.ai_engine import ThreatAnalyzerService
from app.services.auth_verifier import AuthVerifier
from app.services.geo_osint import GeoTrackerService
from app.services.parser import EMLParser, InvalidEmailError
from app.services.phishing_detector import PhishingDetector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["investigation"])

MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {".eml", ".txt"}


# ── Case Management Endpoints ─────────────────────────────────

def _format_case(case: Case) -> dict[str, Any]:
    return {
        "id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "severity": case.severity,
        "threat_type": case.threat_type,
        "created_at": case.created_at.isoformat() if case.created_at else "",
        "updated_at": case.updated_at.isoformat() if case.updated_at else "",
        "email_artifacts": [
            {
                "id": art.id,
                "case_id": art.case_id,
                "filename": art.filename,
                "sha256": art.sha256,
                "subject": art.subject,
                "sender": art.sender,
                "recipient": art.recipient,
                "created_at": art.created_at.isoformat() if art.created_at else "",
            }
            for art in (case.email_artifacts or [])
        ],
        "investigation_results": [
            {
                "id": res.id,
                "case_id": res.case_id,
                "risk_score": res.risk_score,
                "risk_level": res.risk_level,
                "verdict": res.verdict,
                "ai_analysis": res.ai_analysis,
                "created_at": res.created_at.isoformat() if res.created_at else "",
            }
            for res in (case.investigation_results or [])
        ],
        "analyst_notes": [
            {
                "id": note.id,
                "case_id": note.case_id,
                "note": note.note,
                "created_at": note.created_at.isoformat() if note.created_at else "",
            }
            for note in (case.analyst_notes or [])
        ],
        "timeline_events": [
            {
                "id": evt.id,
                "case_id": evt.case_id,
                "event_type": evt.event_type,
                "description": evt.description,
                "timestamp": evt.timestamp.isoformat() if evt.timestamp else "",
                "event_metadata": evt.event_metadata,
            }
            for evt in (case.timeline_events or [])
        ],
    }


@router.post("/cases", response_model=CaseResponse, status_code=status.HTTP_201_CREATED, tags=["cases"])
def create_case(payload: CaseCreate, db: Session = Depends(get_db)) -> CaseResponse:
    case = case_service.create_case(
        db,
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        threat_type=payload.threat_type,
    )
    return CaseResponse.model_validate(_format_case(case))


@router.get("/cases", response_model=list[CaseResponse], tags=["cases"])
def list_cases(db: Session = Depends(get_db)) -> list[CaseResponse]:
    cases = case_service.get_cases(db)
    return [CaseResponse.model_validate(_format_case(c)) for c in cases]


@router.get("/cases/{case_id}", response_model=CaseResponse, tags=["cases"])
def get_case(case_id: int, db: Session = Depends(get_db)) -> CaseResponse:
    case = case_service.get_case(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )
    return CaseResponse.model_validate(_format_case(case))


@router.patch("/cases/{case_id}", response_model=CaseResponse, tags=["cases"])
def update_case(case_id: int, payload: CaseUpdate, db: Session = Depends(get_db)) -> CaseResponse:
    case = case_service.update_case(db, case_id, payload.model_dump(exclude_unset=True))
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )
    return CaseResponse.model_validate(_format_case(case))


@router.delete("/cases/{case_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["cases"])
def delete_case(case_id: int, db: Session = Depends(get_db)) -> None:
    deleted = case_service.delete_case(db, case_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )


@router.post("/cases/{case_id}/notes", response_model=AnalystNoteResponse, status_code=status.HTTP_201_CREATED, tags=["cases"])
def add_analyst_note(case_id: int, payload: AnalystNoteCreate, db: Session = Depends(get_db)) -> AnalystNoteResponse:
    case = case_service.get_case(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )
    note = case_service.add_analyst_note(db, case_id, payload.note)
    return AnalystNoteResponse.model_validate({
        "id": note.id,
        "case_id": note.case_id,
        "note": note.note,
        "created_at": note.created_at.isoformat() if note.created_at else "",
    })


@router.get("/cases/{case_id}/timeline", response_model=TimelineSummaryResponse, tags=["cases"])
def get_case_timeline(case_id: int, db: Session = Depends(get_db)) -> TimelineSummaryResponse:
    """Return real, chronological forensic timeline events for a case."""
    timeline = case_service.get_case_timeline(db, case_id)
    if timeline is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )
    return TimelineSummaryResponse.model_validate(timeline)


# ── Existing Analysis & Investigation Routes ──────────────────

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
    case_id: Annotated[int | None, Form(description="Optional Case ID to attach investigation results to")] = None,
    db: Session = Depends(get_db),
) -> InvestigationResponse:
    filename = file.filename or ""
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml and .txt files are accepted.",
        )

    if case_id is not None:
        existing_case = case_service.get_case(db, case_id)
        if not existing_case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case with ID {case_id} not found.",
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

    # ── Stage timing accumulators ─────────────────────────────
    stage_timings: dict[str, int] = {}

    def ms(start: float) -> int:
        return int((time.perf_counter() - start) * 1000)

    try:
        # ── STAGE 1: Email Parsing ────────────────────────────
        t0 = time.perf_counter()
        email_data = await EMLParser().parse_upload(file)
        stage_timings["parser_ms"] = ms(t0)

        # ── STAGE 2: Authentication analysis ─────────────────
        t0 = time.perf_counter()
        authentication = AuthVerifier().verify(email_data["authentication_results"])
        stage_timings["auth_ms"] = ms(t0)

        # ── STAGE 3: Phishing / IOC detection ────────────────
        t0 = time.perf_counter()
        phishing_assessment = PhishingDetector().analyze(
            urls=email_data.get("urls", []),
            message="\n".join((email_data.get("subject", ""), email_data.get("body", ""))),
            sender=email_data.get("from", ""),
            reply_to=email_data.get("reply_to", ""),
            authentication=authentication,
            link_mismatches=email_data.get("link_mismatches", []),
        )
        stage_timings["phishing_ms"] = ms(t0)

        # ── STAGES 4 & 5: GeoIP + AI (parallel) ──────────────
        t0_geo = time.perf_counter()
        t0_ai = time.perf_counter()
        geo_hops, threat_analysis = await asyncio.gather(
            GeoTrackerService().track_hops(email_data["received_headers"]),
            ThreatAnalyzerService().analyze(
                email_data,
                authentication,
                deterministic_assessment=phishing_assessment,
            ),
        )
        # Approximate: both ran in parallel; record elapsed since each started
        parallel_elapsed_ms = ms(t0_geo)
        stage_timings["geo_ms"] = parallel_elapsed_ms
        stage_timings["ai_ms"] = parallel_elapsed_ms

        # ── STAGE 6: Attack graph ─────────────────────────────
        t0 = time.perf_counter()
        attack_graph = _build_attack_graph(
            email_data=email_data,
            authentication=authentication,
            geo_hops=geo_hops,
            threat_analysis=threat_analysis,
        )
        stage_timings["graph_ms"] = ms(t0)

        payload: dict[str, Any] = {
            "email": email_data,
            "authentication": authentication,
            "geo_hops": geo_hops,
            "threat_analysis": threat_analysis,
            "attack_graph": attack_graph,
        }

        # ── STAGE 7: Evidence hash ────────────────────────────
        t0 = time.perf_counter()
        canonical_payload = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        payload["evidence_hash"] = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        stage_timings["hash_ms"] = ms(t0)

        if case_id is not None:
            case_service.attach_investigation_to_case(
                db=db,
                case_id=case_id,
                email_data=email_data,
                payload=payload,
                filename=filename,
            )
            # Record granular forensic stage events for the timeline
            _record_forensic_stages(
                db=db,
                case_id=case_id,
                email_data=email_data,
                phishing_assessment=phishing_assessment,
                threat_analysis=threat_analysis,
                geo_hops=geo_hops,
                payload=payload,
                stage_timings=stage_timings,
            )

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


# ── Internal: Record forensic stage timeline events ──────────

def _record_forensic_stages(
    db: object,
    case_id: int,
    email_data: dict[str, Any],
    phishing_assessment: dict[str, Any],
    threat_analysis: dict[str, Any],
    geo_hops: list[dict[str, Any]],
    payload: dict[str, Any],
    stage_timings: dict[str, int],
) -> None:
    """Record per-stage forensic timeline events for a case. Called only when case_id is set."""

    from app.db.session import get_db as _get_db  # avoid circular at module level

    stages: list[dict[str, Any]] = []

    # EMAIL_PARSED
    stages.append({
        "event_type": "EMAIL_PARSED",
        "description": (
            f"RFC 5322 parsing completed. Subject: '{email_data.get('subject', '')[:80]}'. "
            f"Sender: {email_data.get('from', 'unknown')}."
        ),
        "metadata": {
            "stage": "parser",
            "duration_ms": stage_timings.get("parser_ms", 0),
            "url_count": len(email_data.get("urls", [])),
            "link_mismatch_count": len(email_data.get("link_mismatches", [])),
            "received_hop_count": len(email_data.get("received_headers", [])),
        },
    })

    # AUTH_ANALYSIS_COMPLETED
    auth = email_data.get("authentication_results", "")
    stages.append({
        "event_type": "AUTH_ANALYSIS_COMPLETED",
        "description": (
            f"SPF/DKIM/DMARC authentication analyzed."
        ),
        "metadata": {
            "stage": "auth_analysis",
            "duration_ms": stage_timings.get("auth_ms", 0),
            "spf": email_data.get("authentication_results", ""),
        },
    })

    # PHISHING_ANALYSIS_COMPLETED
    p_score = phishing_assessment.get("risk_score", phishing_assessment.get("confidence", 0))
    p_level = phishing_assessment.get("risk_level", "unknown")
    p_cls = phishing_assessment.get("classification", "unknown")
    ioc_count = len(phishing_assessment.get("indicators", []))
    stages.append({
        "event_type": "PHISHING_ANALYSIS_COMPLETED",
        "description": (
            f"Phishing analysis completed: {p_cls} ({p_level.upper()}). "
            f"Risk score: {p_score}/100."
        ),
        "metadata": {
            "stage": "phishing_analysis",
            "duration_ms": stage_timings.get("phishing_ms", 0),
            "risk_score": p_score,
            "risk_level": p_level,
            "classification": p_cls,
        },
    })

    # IOC_EXTRACTION_COMPLETED
    stages.append({
        "event_type": "IOC_EXTRACTION_COMPLETED",
        "description": (
            f"{ioc_count} indicator(s) extracted from email headers, body, and URLs."
        ),
        "metadata": {
            "stage": "ioc_extraction",
            "duration_ms": stage_timings.get("phishing_ms", 0),
            "indicator_count": ioc_count,
            "url_count": len(phishing_assessment.get("urls", [])),
        },
    })

    # GEOINT_COMPLETED or GEOINT_UNAVAILABLE
    if geo_hops:
        stages.append({
            "event_type": "GEOINT_COMPLETED",
            "description": (
                f"GeoIP intelligence resolved {len(geo_hops)} relay hop(s). "
                f"First relay: {geo_hops[0].get('ip', 'unknown')} "
                f"({geo_hops[0].get('country', 'unknown')})."
            ),
            "metadata": {
                "stage": "geoint",
                "duration_ms": stage_timings.get("geo_ms", 0),
                "hop_count": len(geo_hops),
                "first_ip": geo_hops[0].get("ip", ""),
                "first_country": geo_hops[0].get("country", ""),
            },
        })
    else:
        stages.append({
            "event_type": "GEOINT_UNAVAILABLE",
            "description": "No received relay headers found or GeoIP service did not respond. No hops enriched.",
            "metadata": {
                "stage": "geoint",
                "duration_ms": stage_timings.get("geo_ms", 0),
                "hop_count": 0,
            },
        })

    # AI_ANALYSIS_COMPLETED or AI_ANALYSIS_SKIPPED
    ta_classification = threat_analysis.get("classification", "")
    ta_score = threat_analysis.get("confidence_score", 0)
    ta_explanation = threat_analysis.get("explanation", "")
    # Heuristic: if explanation contains "heuristic" or "fallback" it means Groq was skipped
    ai_used = "heuristic" not in ta_explanation.lower() and "fallback" not in ta_explanation.lower()
    if ai_used:
        stages.append({
            "event_type": "AI_ANALYSIS_COMPLETED",
            "description": (
                f"AI threat assessment completed. Classification: {ta_classification}, "
                f"Confidence: {ta_score}/100."
            ),
            "metadata": {
                "stage": "ai_analysis",
                "duration_ms": stage_timings.get("ai_ms", 0),
                "classification": ta_classification,
                "confidence_score": ta_score,
                "mitre_mapping": threat_analysis.get("mitre_attack_mapping", ""),
            },
        })
    else:
        stages.append({
            "event_type": "AI_ANALYSIS_SKIPPED",
            "description": (
                "Groq LLM enrichment was unavailable or not configured. "
                f"Deterministic heuristic analysis completed: {ta_classification}, score {ta_score}/100."
            ),
            "metadata": {
                "stage": "ai_analysis",
                "duration_ms": stage_timings.get("ai_ms", 0),
                "classification": ta_classification,
                "confidence_score": ta_score,
                "fallback": True,
            },
        })

    # ATTACK_GRAPH_GENERATED
    graph = payload.get("attack_graph", {})
    node_count = len(graph.get("nodes", []))
    link_count = len(graph.get("links", []))
    stages.append({
        "event_type": "ATTACK_GRAPH_GENERATED",
        "description": (
            f"Attack graph generated with {node_count} nodes and {link_count} edges "
            "showing email propagation path."
        ),
        "metadata": {
            "stage": "attack_graph",
            "duration_ms": stage_timings.get("graph_ms", 0),
            "node_count": node_count,
            "link_count": link_count,
        },
    })

    # EVIDENCE_HASH_GENERATED
    stages.append({
        "event_type": "EVIDENCE_HASH_GENERATED",
        "description": (
            f"SHA-256 evidence digest sealed: {payload.get('evidence_hash', '')[:16]}..."
        ),
        "metadata": {
            "stage": "evidence_hash",
            "duration_ms": stage_timings.get("hash_ms", 0),
            "sha256_prefix": payload.get("evidence_hash", "")[:16],
        },
    })

    case_service.record_investigation_timeline_events(db, case_id, stages)


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
