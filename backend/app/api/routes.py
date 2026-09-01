from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from email.utils import getaddresses
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.db.models import Case
from app.db.session import get_db
from app.models.schemas import (
    AnalystNoteCreate,
    AnalystNoteResponse,
    CampaignDetectionResponse,
    CampaignListItem,
    CampaignListResponse,
    CampaignProfile,
    CaseCreate,
    CaseResponse,
    CaseUpdate,
    InvestigationResponse,
    LedgerEntryResponse,
    LedgerSummaryResponse,
    LedgerVerificationResponse,
    PhishingScanRequest,
    PhishingScanResponse,
    TimelineSummaryResponse,
)
from app.services import case_service, evidence_ledger
from app.services.ai_engine import ThreatAnalyzerService
from app.services.auth_verifier import AuthVerifier
from app.services.campaign_detector import CampaignDetectionService
from app.services.geo_osint import GeoTrackerService
from app.services.parser import EMLParser, InvalidEmailError
from app.services.phishing_detector import PhishingDetector
from app.services.threat_intelligence import ThreatIntelligenceService

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


# ── Evidence Ledger Endpoints ────────────────────────────────

@router.get("/cases/{case_id}/ledger", response_model=LedgerSummaryResponse, tags=["ledger"])
def get_case_ledger_summary(case_id: int, db: Session = Depends(get_db)) -> LedgerSummaryResponse:
    """Return all chained blocks in the case's cryptographic Evidence Ledger."""
    case = case_service.get_case(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    verification = evidence_ledger.verify_case_ledger(db, case_id)
    entries = evidence_ledger.get_case_ledger(db, case_id)
    serialized_entries = [
        LedgerEntryResponse(
            id=e.id,
            case_id=e.case_id,
            sequence_number=e.sequence_number,
            entry_type=e.entry_type,
            reference_id=e.reference_id,
            data_hash=e.data_hash,
            previous_hash=e.previous_hash,
            entry_hash=e.entry_hash,
            metadata_json=e.metadata_json,
            timestamp=e.timestamp.isoformat() if e.timestamp else "",
        )
        for e in entries
    ]

    return LedgerSummaryResponse(
        case_id=case.id,
        case_number=case.case_number,
        total_entries=len(entries),
        is_valid=verification["is_valid"],
        status=verification["status"],
        merkle_root=verification.get("merkle_root") or "0" * 64,
        latest_entry_hash=verification.get("latest_entry_hash"),
        entries=serialized_entries,
    )


@router.get("/cases/{case_id}/ledger/verify", response_model=LedgerVerificationResponse, tags=["ledger"])
def verify_case_ledger_integrity(case_id: int, db: Session = Depends(get_db)) -> LedgerVerificationResponse:
    """Cryptographically verify the hash chain and Merkle root of the case evidence ledger."""
    res = evidence_ledger.verify_case_ledger(db, case_id)
    if res.get("status") == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=res.get("message", "Case not found."),
        )
    return LedgerVerificationResponse.model_validate(res)


# ── Campaign Management Endpoints ────────────────────────────

def _load_email_items_from_db(db: Session, case_id: int | None = None) -> list[dict[str, Any]]:
    """Loads normalized email artifacts with parsed investigation payloads from SQLite."""
    if case_id is not None:
        case = case_service.get_case(db, case_id)
        if not case:
            return []
        artifacts = case.email_artifacts
    else:
        cases = case_service.get_cases(db)
        artifacts = []
        for c in cases:
            artifacts.extend(c.email_artifacts)

    items: list[dict[str, Any]] = []
    for art in artifacts:
        inv_payload: dict[str, Any] = {}
        if art.case and art.case.investigation_results:
            # Find the closest matching investigation result
            for inv in art.case.investigation_results:
                try:
                    parsed = json.loads(inv.ai_analysis)
                    if isinstance(parsed, dict):
                        inv_payload = parsed
                        break
                except Exception:
                    pass

        email_meta = inv_payload.get("email", {})
        items.append({
            "id": art.id,
            "artifact_id": art.id,
            "case_id": art.case_id,
            "subject": art.subject or email_meta.get("subject", ""),
            "sender": art.sender or email_meta.get("from", ""),
            "recipient": art.recipient or email_meta.get("to", ""),
            "reply_to": email_meta.get("reply_to", ""),
            "created_at": art.created_at.isoformat() if art.created_at else "",
            "payload": inv_payload,
            "received_headers": email_meta.get("received_headers", []),
            "urls": email_meta.get("urls", []),
            "geo_hops": inv_payload.get("geo_hops", []),
            "threat_intelligence": inv_payload.get("threat_intelligence", []),
            "threat_analysis": inv_payload.get("threat_analysis", {}),
            "authentication": inv_payload.get("authentication", {}),
            "verdict": art.case.threat_type if art.case else "phishing",
            "risk_score": art.case.investigation_results[0].risk_score if art.case and art.case.investigation_results else 70,
        })
    return items


@router.post("/cases/{case_id}/campaigns/detect", response_model=CampaignDetectionResponse)
def detect_case_campaigns(case_id: int, db: Session = Depends(get_db)) -> CampaignDetectionResponse:
    """Runs cross-email correlation across all email artifacts in a case and records timeline event."""
    case = case_service.get_case(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    items = _load_email_items_from_db(db, case_id=case_id)
    result = CampaignDetectionService().detect_campaigns(items, case_id=case_id)

    # Persist detected campaigns
    persisted_campaigns = []
    for camp_data in result["campaigns"]:
        saved = case_service.save_or_update_campaign(db, camp_data, case_id=case_id)
        camp_dict = json.loads(saved.data)
        camp_dict["id"] = saved.id
        persisted_campaigns.append(CampaignProfile.model_validate(camp_dict))

    result["campaigns"] = persisted_campaigns

    # Record Case 2 forensic timeline event
    if result["status"] == "completed":
        case_service.add_timeline_event(
            db,
            case_id=case_id,
            event_type="CAMPAIGN_DETECTION_COMPLETED",
            description=f"Campaign detection completed: {result['campaigns_detected']} campaign(s) detected across {result['emails_analyzed']} emails ({result['shared_iocs']} shared IOCs).",
            event_metadata={
                "emails_analyzed": result["emails_analyzed"],
                "campaigns_detected": result["campaigns_detected"],
                "high_confidence_campaigns": result["high_confidence_campaigns"],
                "shared_iocs": result["shared_iocs"],
            },
        )
    else:
        case_service.add_timeline_event(
            db,
            case_id=case_id,
            event_type="CAMPAIGN_DETECTION_UNAVAILABLE",
            description=f"Campaign detection unavailable: {result['message']}",
            event_metadata={
                "emails_analyzed": result["emails_analyzed"],
                "reason": result["status"],
            },
        )

    return CampaignDetectionResponse.model_validate(result)


@router.post("/campaigns/detect", response_model=CampaignDetectionResponse)
def detect_all_campaigns(
    case_id: int | None = None,
    db: Session = Depends(get_db),
) -> CampaignDetectionResponse:
    """Runs cross-email correlation across all cases or a specified case."""
    if case_id is not None:
        return detect_case_campaigns(case_id=case_id, db=db)

    items = _load_email_items_from_db(db, case_id=None)
    result = CampaignDetectionService().detect_campaigns(items, case_id=None)

    persisted_campaigns = []
    for camp_data in result["campaigns"]:
        saved = case_service.save_or_update_campaign(db, camp_data, case_id=None)
        camp_dict = json.loads(saved.data)
        camp_dict["id"] = saved.id
        persisted_campaigns.append(CampaignProfile.model_validate(camp_dict))

    result["campaigns"] = persisted_campaigns
    return CampaignDetectionResponse.model_validate(result)


@router.get("/campaigns", response_model=CampaignListResponse)
def list_campaigns(
    case_id: int | None = None,
    db: Session = Depends(get_db),
) -> CampaignListResponse:
    """Retrieves all persisted campaigns with SOC aggregate metrics."""
    camps = case_service.get_campaigns(db, case_id=case_id)
    items = []
    total_emails = 0
    total_iocs = 0
    high_conf = 0

    for c in camps:
        items.append(
            CampaignListItem(
                id=c.id,
                campaign_id=c.campaign_id,
                case_id=c.case_id,
                name=c.name,
                status=c.status,
                threat_type=c.threat_type,
                confidence=c.confidence,
                email_count=c.email_count,
                shared_ioc_count=c.shared_ioc_count,
                shared_infrastructure_count=c.shared_infrastructure_count,
                created_at=c.created_at.isoformat() if c.created_at else "",
                updated_at=c.updated_at.isoformat() if c.updated_at else "",
            )
        )
        total_emails += c.email_count
        total_iocs += c.shared_ioc_count
        if c.confidence >= 85:
            high_conf += 1

    return CampaignListResponse(
        total_campaigns=len(items),
        high_confidence_count=high_conf,
        total_emails_correlated=total_emails,
        total_shared_iocs=total_iocs,
        campaigns=items,
    )


@router.get("/campaigns/{campaign_id}", response_model=CampaignProfile)
def get_campaign(campaign_id: str, db: Session = Depends(get_db)) -> CampaignProfile:
    """Retrieves full campaign profile by unique ID or database ID."""
    camp = case_service.get_campaign(db, campaign_id)
    if not camp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Campaign with ID '{campaign_id}' not found.",
        )
    profile_data = json.loads(camp.data)
    profile_data["id"] = camp.id
    return CampaignProfile.model_validate(profile_data)


@router.get("/cases/{case_id}/campaigns", response_model=CampaignListResponse)
def list_case_campaigns(case_id: int, db: Session = Depends(get_db)) -> CampaignListResponse:
    """Retrieves all campaigns associated with a specific case."""
    case = case_service.get_case(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )
    return list_campaigns(case_id=case_id, db=db)


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

        # ── STAGE 6: Threat Intelligence & IOC Enrichment ────
        t0_intel = time.perf_counter()
        threat_intelligence = await ThreatIntelligenceService().enrich_all(
            email_data=email_data,
            phishing_assessment=phishing_assessment.model_dump() if hasattr(phishing_assessment, "model_dump") else phishing_assessment,
            geo_hops=geo_hops,
            authentication=authentication,
        )
        stage_timings["intel_ms"] = ms(t0_intel)

        # ── STAGE 7: Attack graph ─────────────────────────────
        t0 = time.perf_counter()
        attack_graph = _build_attack_graph(
            email_data=email_data,
            authentication=authentication,
            geo_hops=geo_hops,
            threat_analysis=threat_analysis,
            threat_intelligence=threat_intelligence,
        )
        stage_timings["graph_ms"] = ms(t0)

        payload: dict[str, Any] = {
            "email": email_data,
            "authentication": authentication,
            "geo_hops": geo_hops,
            "threat_analysis": threat_analysis,
            "attack_graph": attack_graph,
            "threat_intelligence": threat_intelligence,
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
            evidence_ledger.record_ledger_entry(
                db=db,
                case_id=case_id,
                entry_type="EVIDENCE_SUBMITTED",
                data_or_hash=payload.get("evidence_hash", ""),
                reference_id=filename or email_data.get("message_id") or "uploaded.eml",
                metadata={"filename": filename, "subject": email_data.get("subject", ""), "sender": email_data.get("from", "")},
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
    ai_used = bool(threat_analysis.get("ai_used", False))
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

    # THREAT_INTELLIGENCE_COMPLETED or THREAT_INTELLIGENCE_UNAVAILABLE
    threat_intel = payload.get("threat_intelligence", [])
    if threat_intel:
        malicious_count = sum(1 for i in threat_intel if i.get("status") == "malicious")
        suspicious_count = sum(1 for i in threat_intel if i.get("status") == "suspicious")
        unknown_count = sum(1 for i in threat_intel if i.get("status") in ("unknown", "unavailable"))
        stages.append({
            "event_type": "THREAT_INTELLIGENCE_COMPLETED",
            "description": (
                f"Threat intelligence enriched {len(threat_intel)} observables. "
                f"Identified {malicious_count} malicious, {suspicious_count} suspicious, {unknown_count} unrated/neutral."
            ),
            "metadata": {
                "stage": "threat_intelligence",
                "duration_ms": stage_timings.get("intel_ms", 0),
                "ioc_count": len(threat_intel),
                "enriched": len(threat_intel),
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "unknown": unknown_count,
            },
        })
    else:
        stages.append({
            "event_type": "THREAT_INTELLIGENCE_UNAVAILABLE",
            "description": "No actionable IOC observables discovered for threat intelligence enrichment.",
            "metadata": {
                "stage": "threat_intelligence",
                "duration_ms": stage_timings.get("intel_ms", 0),
                "ioc_count": 0,
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
    threat_intelligence: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    threat_intelligence = threat_intelligence or []
    intel_by_indicator = {i.get("indicator", "").lower().strip(): i for i in threat_intelligence}

    nodes_by_id: dict[str, dict[str, Any]] = {}
    links: list[dict[str, Any]] = []
    seen_links: set[tuple[str, str, str]] = set()

    def add_node(node: dict[str, Any]) -> None:
        node_id = node["id"]
        if node_id not in nodes_by_id:
            nodes_by_id[node_id] = node
        else:
            # Merge any richer metadata if present
            for k, v in node.items():
                if v is not None and (nodes_by_id[node_id].get(k) is None or nodes_by_id[node_id].get(k) in ("Unknown", "unknown", 0, "")):
                    nodes_by_id[node_id][k] = v

    def add_link(source: str, target: str, relation: str) -> None:
        key = (source, target, relation)
        if key not in seen_links and source in nodes_by_id and target in nodes_by_id:
            seen_links.add(key)
            links.append({"source": source, "target": target, "relation": relation})

    # 1. Email Node (Central Subject)
    message_id = email_data.get("message_id") or "uploaded-email"
    email_node_id = f"email:{message_id}"
    add_node({
        "id": email_node_id,
        "name": email_data.get("subject") or "Email message",
        "type": "email",
        "message_id": message_id,
        "date": email_data.get("date", ""),
        "status": "malicious" if threat_analysis.get("risk_level") in ("critical", "high") else "suspicious" if threat_analysis.get("risk_level") == "medium" else "benign",
        "confidence": threat_analysis.get("confidence", threat_analysis.get("confidence_score", 0)),
    })

    # 2. Sender & Sender Domain
    sender = _first_address(email_data.get("from", ""))
    sender_id = f"sender:{sender.lower()}" if sender else None
    if sender:
        sender_intel = intel_by_indicator.get(sender.lower())
        sender_node = {
            "id": sender_id,
            "name": sender,
            "type": "sender",
            "status": sender_intel.get("status", "unknown") if sender_intel else "unknown",
            "confidence": sender_intel.get("confidence", 0) if sender_intel else 0,
            "source": sender_intel.get("source", "Local Analysis") if sender_intel else "Local Analysis",
            "reasons": sender_intel.get("reasons", []) if sender_intel else [],
        }
        add_node(sender_node)

        # Domain node for sender
        if "@" in sender:
            sender_domain = sender.split("@")[-1].lower().strip(">")
            domain_id = f"domain:{sender_domain}"
            domain_intel = intel_by_indicator.get(sender_domain)
            add_node({
                "id": domain_id,
                "name": sender_domain,
                "type": "domain",
                "status": domain_intel.get("status", "unknown") if domain_intel else "unknown",
                "confidence": domain_intel.get("confidence", 0) if domain_intel else 0,
                "source": domain_intel.get("source", "Local Analysis") if domain_intel else "Local Analysis",
                "reasons": domain_intel.get("reasons", []) if domain_intel else [],
            })
            add_link(sender_id, domain_id, "BELONGS_TO_DOMAIN")

    # 3. Recipients
    for recipient in _addresses(email_data.get("to", "")):
        recipient_id = f"recipient:{recipient.lower()}"
        add_node({
            "id": recipient_id,
            "name": recipient,
            "type": "recipient",
            "status": "benign",
            "confidence": 100,
        })
        add_link(email_node_id, recipient_id, "DELIVERED_TO")

    # 4. Sequential Relay Hop-Chain (Chronological: Origin -> Intermediate -> Destination MX)
    # RFC 5322 received headers appear top-to-bottom (newest first). Reversing gives chronological order.
    chronological_headers = list(reversed(email_data.get("received_headers", [])))
    relay_ips_in_order: list[str] = []
    seen_ips: set[str] = set()

    for header in chronological_headers:
        for candidate in re.findall(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", header):
            if candidate not in seen_ips:
                seen_ips.add(candidate)
                relay_ips_in_order.append(candidate)

    # Fallback to geo_hops if no header regex match
    if not relay_ips_in_order and geo_hops:
        relay_ips_in_order = [h["ip"] for h in geo_hops if h.get("ip")]

    geo_map = {h["ip"]: h for h in geo_hops if "ip" in h}
    relay_node_ids: list[str] = []

    for ip in relay_ips_in_order:
        hop = geo_map.get(ip, {})
        ip_intel = intel_by_indicator.get(ip)
        location = ", ".join(
            value for value in (hop.get("city"), hop.get("country")) if value and value != "Unknown"
        )
        ip_node_id = f"ip:{ip}"
        relay_node_ids.append(ip_node_id)
        add_node({
            "id": ip_node_id,
            "name": f"{ip} ({location})" if location else ip,
            "type": "relay_ip",
            "ip": ip,
            "country": hop.get("country", "Unknown"),
            "city": hop.get("city", "Unknown"),
            "isp": hop.get("isp", "Unknown"),
            "asn": hop.get("asn", "Unknown"),
            "status": ip_intel.get("status", "unknown") if ip_intel else "unknown",
            "confidence": ip_intel.get("confidence", 0) if ip_intel else 0,
            "source": ip_intel.get("source", "Local Analysis") if ip_intel else "Local Analysis",
            "reasons": ip_intel.get("reasons", []) if ip_intel else [],
        })

    # Sequential relay chain linking
    if relay_node_ids:
        # Link sender to first originating relay
        if sender_id:
            add_link(sender_id, relay_node_ids[0], "ORIGINATES_FROM")

        # Link sequential hops: Hop 1 -> Hop 2 -> Hop 3
        for i in range(len(relay_node_ids) - 1):
            add_link(relay_node_ids[i], relay_node_ids[i + 1], "RELAYED_TO")

        # Link final gateway hop to email node
        add_link(relay_node_ids[-1], email_node_id, "DELIVERED_VIA")
    elif sender_id:
        # If no relay IPs observed, fallback direct link
        add_link(sender_id, email_node_id, "SENT")

    # 5. Embedded URLs & Domain Correlation
    seen_urls: set[str] = set()
    url_items: list[dict[str, Any]] = []

    for intel in threat_intelligence:
        if intel.get("type") == "url":
            url_val = intel.get("indicator", "").strip()
            if url_val and url_val not in seen_urls:
                seen_urls.add(url_val)
                url_items.append(intel)

    for u in email_data.get("urls", []):
        u_clean = u.strip() if u else ""
        if u_clean and u_clean not in seen_urls:
            seen_urls.add(u_clean)
            u_intel = intel_by_indicator.get(u_clean.lower())
            url_items.append(u_intel or {
                "indicator": u_clean,
                "type": "url",
                "status": "suspicious",
                "confidence": 75,
                "source": "Local Analysis",
                "reasons": ["Extracted from message body"],
            })

    for intel in url_items:
        url_val = intel.get("indicator", "")
        url_node_id = f"url:{url_val}"
        add_node({
            "id": url_node_id,
            "name": url_val[:45] + ("..." if len(url_val) > 45 else ""),
            "type": "url",
            "indicator": url_val,
            "status": intel.get("status", "unknown"),
            "confidence": intel.get("confidence", 0),
            "source": intel.get("source", "Local Analysis"),
            "reasons": intel.get("reasons", []),
        })
        add_link(email_node_id, url_node_id, "EMBEDS_URL")

        # Extract URL domain and link URL -> Domain
        url_domain = _url_to_domain(url_val)
        if url_domain:
            url_domain_id = f"domain:{url_domain}"
            domain_intel = intel_by_indicator.get(url_domain)
            add_node({
                "id": url_domain_id,
                "name": url_domain,
                "type": "domain",
                "status": domain_intel.get("status", intel.get("status", "unknown")) if domain_intel else intel.get("status", "unknown"),
                "confidence": domain_intel.get("confidence", intel.get("confidence", 0)) if domain_intel else intel.get("confidence", 0),
                "source": domain_intel.get("source", "Local Analysis") if domain_intel else "Local Analysis",
                "reasons": domain_intel.get("reasons", []) if domain_intel else [],
            })
            add_link(url_node_id, url_domain_id, "HOSTED_ON")

    # 6. Authentication Results Node
    auth_id = "authentication:results"
    auth_name = " | ".join(
        f"{mechanism.upper()}: {'pass' if passed else 'fail'}"
        for mechanism, passed in authentication.items()
    )
    auth_status = "benign" if all(v == "pass" for v in authentication.values()) else "suspicious" if any(v == "fail" for v in authentication.values()) else "unknown"
    add_node({
        "id": auth_id,
        "name": auth_name,
        "type": "authentication",
        "status": auth_status,
        "confidence": 90,
    })
    add_link(auth_id, email_node_id, "VALIDATES")

    # 7. Threat Assessment Node (AI + Technical Risk)
    threat_id = "threat:assessment"
    det = threat_analysis.get("deterministic_assessment") or {}
    ta_status = "malicious" if threat_analysis.get("risk_level") in ("critical", "high") else "suspicious" if threat_analysis.get("risk_level") == "medium" else "benign"
    add_node({
        "id": threat_id,
        "name": f"Verdict: {threat_analysis.get('threat_type', threat_analysis.get('classification', 'Threat Assessment'))}",
        "type": "threat_assessment",
        "status": ta_status,
        "confidence_score": threat_analysis.get("confidence", threat_analysis.get("confidence_score", 0)),
        "threat_type": threat_analysis.get("threat_type", threat_analysis.get("classification", "Unknown")),
        "deterministic_risk": det.get("risk_score") if isinstance(det, dict) else getattr(det, "risk_score", None),
        "summary": threat_analysis.get("summary") or threat_analysis.get("explanation", ""),
    })
    add_link(threat_id, email_node_id, "ASSESSES")

    return {"nodes": list(nodes_by_id.values()), "links": links}


def _url_to_domain(url_str: str) -> str:
    """Extracts hostname domain from URL."""
    try:
        candidate = url_str.strip()
        candidate = candidate.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
        if "://" not in candidate:
            candidate = f"http://{candidate}"
        return (urlsplit(candidate).hostname or "").lower().strip("[]/")
    except (ValueError, Exception):
        return ""


def _addresses(header_value: str) -> list[str]:
    addresses = [address for _, address in getaddresses([header_value]) if address]
    return list(dict.fromkeys(addresses))


def _first_address(header_value: str) -> str:
    addresses = _addresses(header_value)
    return addresses[0] if addresses else header_value.strip()
