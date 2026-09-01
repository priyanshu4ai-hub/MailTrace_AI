from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AnalystNote, Campaign, Case, EmailArtifact, InvestigationResult, TimelineEvent


def generate_case_number(db: Session) -> str:
    year = datetime.now(timezone.utc).year
    prefix = f"MT-{year}-"
    
    stmt = select(Case.case_number).where(Case.case_number.like(f"{prefix}%"))
    existing_numbers = db.scalars(stmt).all()
    
    max_seq = 0
    for num in existing_numbers:
        try:
            seq_part = num.split("-")[-1]
            seq_val = int(seq_part)
            if seq_val > max_seq:
                max_seq = seq_val
        except (ValueError, IndexError):
            continue
            
    next_seq = max_seq + 1
    return f"{prefix}{next_seq:04d}"


def create_case(
    db: Session,
    title: str,
    description: str = "",
    severity: str = "medium",
    threat_type: str = "phishing",
) -> Case:
    case_number = generate_case_number(db)
    case = Case(
        case_number=case_number,
        title=title.strip(),
        description=description.strip(),
        status="open",
        severity=severity.lower().strip(),
        threat_type=threat_type.lower().strip(),
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    add_timeline_event(
        db,
        case_id=case.id,
        event_type="CASE_CREATED",
        description=f"Case {case.case_number} created with severity '{case.severity}'.",
        event_metadata={"title": case.title, "threat_type": case.threat_type},
    )
    db.refresh(case)
    return case


def get_cases(db: Session) -> list[Case]:
    stmt = select(Case).order_by(Case.created_at.desc())
    return list(db.scalars(stmt).all())


def get_case(db: Session, case_id: int) -> Case | None:
    return db.get(Case, case_id)


def update_case(db: Session, case_id: int, updates: dict[str, Any]) -> Case | None:
    case = get_case(db, case_id)
    if not case:
        return None

    changed_fields = []
    for field in ("title", "description", "status", "severity", "threat_type"):
        if field in updates and updates[field] is not None:
            old_val = getattr(case, field)
            new_val = str(updates[field]).strip()
            if field in ("status", "severity", "threat_type"):
                new_val = new_val.lower()
            if old_val != new_val:
                setattr(case, field, new_val)
                changed_fields.append(f"{field}: '{old_val}' -> '{new_val}'")

    if changed_fields:
        case.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(case)
        add_timeline_event(
            db,
            case_id=case.id,
            event_type="CASE_UPDATED",
            description=f"Case updated: {', '.join(changed_fields)}",
            event_metadata=updates,
        )
        db.refresh(case)

    return case


def delete_case(db: Session, case_id: int) -> bool:
    case = get_case(db, case_id)
    if not case:
        return False

    db.delete(case)
    db.commit()
    return True


def add_timeline_event(
    db: Session,
    case_id: int,
    event_type: str,
    description: str,
    event_metadata: dict[str, Any] | None = None,
) -> TimelineEvent:
    event = TimelineEvent(
        case_id=case_id,
        event_type=event_type,
        description=description,
        timestamp=datetime.now(timezone.utc),
        event_metadata=json.dumps(event_metadata or {}),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def add_analyst_note(db: Session, case_id: int, note: str) -> AnalystNote:
    analyst_note = AnalystNote(
        case_id=case_id,
        note=note.strip(),
        created_at=datetime.now(timezone.utc),
    )
    db.add(analyst_note)
    db.commit()
    db.refresh(analyst_note)

    add_timeline_event(
        db,
        case_id=case_id,
        event_type="ANALYST_NOTE_ADDED",
        description=f"Analyst note added: {note[:60]}..." if len(note) > 60 else f"Analyst note added: {note}",
    )

    return analyst_note


def attach_investigation_to_case(
    db: Session,
    case_id: int,
    email_data: dict[str, Any],
    payload: dict[str, Any],
    filename: str = "",
) -> tuple[EmailArtifact, InvestigationResult]:
    case = get_case(db, case_id)
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    raw_body = str(email_data.get("body", ""))
    subject = str(email_data.get("subject", ""))
    sender = str(email_data.get("from", ""))
    recipient = str(email_data.get("to", ""))

    sha256_hash = payload.get("evidence_hash")
    if not sha256_hash:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        sha256_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    artifact = EmailArtifact(

        case_id=case.id,
        filename=filename or email_data.get("message_id") or "uploaded.eml",
        sha256=sha256_hash,
        subject=subject,
        sender=sender,
        recipient=recipient,
        raw_content=raw_body,
        created_at=datetime.now(timezone.utc),
    )
    db.add(artifact)

    threat_analysis = payload.get("threat_analysis", {})
    risk_score = threat_analysis.get("confidence_score", 0)
    risk_level = threat_analysis.get("risk_level", "safe")
    verdict = threat_analysis.get("classification", "benign")

    investigation_result = InvestigationResult(
        case_id=case.id,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        ai_analysis=json.dumps(payload, ensure_ascii=False),
        created_at=datetime.now(timezone.utc),
    )
    db.add(investigation_result)

    case.threat_type = verdict.lower()
    if risk_score >= 80 or verdict.lower() in ("phishing", "bec"):
        case.severity = "high" if case.severity != "critical" else "critical"
    case.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(artifact)
    db.refresh(investigation_result)

    add_timeline_event(
        db,
        case_id=case.id,
        event_type="EMAIL_UPLOADED",
        description=f"Email artifact '{artifact.filename}' uploaded (SHA-256: {sha256_hash[:16]}...).",
        event_metadata={
            "artifact_id": artifact.id,
            "filename": artifact.filename,
            "sha256": sha256_hash,
            "subject": subject,
            "sender": sender,
        },
    )

    add_timeline_event(
        db,
        case_id=case.id,
        event_type="INVESTIGATION_COMPLETED",
        description=f"Forensic triage completed: Verdict={verdict}, Risk Score={risk_score}/100 ({risk_level.upper()}).",
        event_metadata={
            "result_id": investigation_result.id,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_level": risk_level,
        },
    )

    return artifact, investigation_result



def get_case_timeline(db: Session, case_id: int) -> dict[str, Any] | None:
    """Return chronologically sorted timeline events with summary metadata for a case."""
    case = get_case(db, case_id)
    if not case:
        return None

    stmt = (
        select(TimelineEvent)
        .where(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.timestamp.asc())
    )
    events = list(db.scalars(stmt).all())

    serialized_events = [
        {
            "id": evt.id,
            "case_id": evt.case_id,
            "event_type": evt.event_type,
            "description": evt.description,
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else "",
            "event_metadata": evt.event_metadata,
        }
        for evt in events
    ]

    first_event_at: str | None = None
    last_event_at: str | None = None
    total_duration_ms: int | None = None

    if events:
        first_event_at = events[0].timestamp.isoformat() if events[0].timestamp else None
        last_event_at = events[-1].timestamp.isoformat() if events[-1].timestamp else None
        if events[0].timestamp and events[-1].timestamp:
            delta = events[-1].timestamp - events[0].timestamp
            total_duration_ms = int(delta.total_seconds() * 1000)

    return {
        "case_id": case.id,
        "case_number": case.case_number,
        "total_events": len(events),
        "first_event_at": first_event_at,
        "last_event_at": last_event_at,
        "total_duration_ms": total_duration_ms,
        "events": serialized_events,
    }


def record_investigation_timeline_events(
    db: Session,
    case_id: int,
    stages: list[dict[str, Any]],
) -> None:
    """
    Persist forensic stage events after investigation completes.
    Each stage dict must have: event_type, description, metadata (optional).
    Stages are recorded in order with incrementing timestamps.
    """
    for stage in stages:
        add_timeline_event(
            db,
            case_id=case_id,
            event_type=stage["event_type"],
            description=stage["description"],
            event_metadata=stage.get("metadata", {}),
        )


def save_or_update_campaign(
    db: Session,
    campaign_data: dict[str, Any],
    case_id: int | None = None,
) -> Campaign:
    """Persists or updates a campaign in the database."""
    camp_id_str = campaign_data.get("campaign_id") or "MT-CAMP-UNKNOWN"
    stmt = select(Campaign).where(Campaign.campaign_id == camp_id_str)
    existing = db.scalars(stmt).first()

    raw_json = json.dumps(campaign_data, ensure_ascii=False)
    name = campaign_data.get("name", "Correlated Threat Campaign")
    status_val = campaign_data.get("status", "detected")
    threat_type = campaign_data.get("threat_type", "Unknown")
    confidence = campaign_data.get("confidence", 0)
    email_count = campaign_data.get("email_count", len(campaign_data.get("emails", [])))
    shared_ioc_count = campaign_data.get("shared_ioc_count", len(campaign_data.get("shared_indicators", [])))
    shared_infra_count = campaign_data.get("shared_infrastructure_count", 0)

    if existing:
        existing.name = name
        existing.status = status_val
        existing.threat_type = threat_type
        existing.confidence = confidence
        existing.email_count = email_count
        existing.shared_ioc_count = shared_ioc_count
        existing.shared_infrastructure_count = shared_infra_count
        existing.data = raw_json
        existing.updated_at = datetime.now(timezone.utc)
        if case_id and not existing.case_id:
            existing.case_id = case_id
        db.commit()
        db.refresh(existing)
        return existing

    new_campaign = Campaign(
        campaign_id=camp_id_str,
        case_id=case_id,
        name=name,
        status=status_val,
        threat_type=threat_type,
        confidence=confidence,
        email_count=email_count,
        shared_ioc_count=shared_ioc_count,
        shared_infrastructure_count=shared_infra_count,
        data=raw_json,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(new_campaign)
    db.commit()
    db.refresh(new_campaign)
    return new_campaign


def get_campaigns(db: Session, case_id: int | None = None) -> list[Campaign]:
    """Returns campaigns, optionally filtered by case_id."""
    stmt = select(Campaign)
    if case_id is not None:
        stmt = stmt.where(Campaign.case_id == case_id)
    stmt = stmt.order_by(Campaign.created_at.desc())
    return list(db.scalars(stmt).all())


def get_campaign(db: Session, identifier: str | int) -> Campaign | None:
    """Retrieves a campaign by its integer ID or unique campaign_id string."""
    if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
        camp = db.get(Campaign, int(identifier))
        if camp:
            return camp
    stmt = select(Campaign).where(Campaign.campaign_id == str(identifier))
    return db.scalars(stmt).first()

