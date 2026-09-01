from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Case, ResponseAction
from app.services import case_service, evidence_ledger


def generate_response_id(db: Session, offset: int = 0) -> str:
    """Generate sequential response action ID: RSP-YYYY-XXXX.
    The offset parameter allows batch creation without UNIQUE conflicts.
    """
    year = datetime.now(timezone.utc).year
    prefix = f"RSP-{year}-"

    stmt = select(ResponseAction.response_id).where(ResponseAction.response_id.like(f"{prefix}%"))
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

    next_seq = max_seq + 1 + offset
    return f"{prefix}{next_seq:04d}"


def get_case_responses(db: Session, case_id: int) -> list[ResponseAction]:
    """Retrieve all response actions for a case ordered by created_at descending."""
    stmt = (
        select(ResponseAction)
        .where(ResponseAction.case_id == case_id)
        .order_by(ResponseAction.created_at.desc())
    )
    return list(db.scalars(stmt).all())


def get_response(db: Session, identifier: str | int) -> ResponseAction | None:
    """Retrieve a response action by ID or unique response_id string."""
    if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
        r = db.get(ResponseAction, int(identifier))
        if r:
            return r
    stmt = select(ResponseAction).where(ResponseAction.response_id == str(identifier))
    return db.scalars(stmt).first()


def generate_case_recommendations(db: Session, case_id: int) -> list[ResponseAction]:
    """
    Analyzes actual persisted case findings (Cases 1–8) and generates deterministic,
    explainable response recommendations in RECOMMENDED status.
    Guarantees:
      - Malicious IOCs generate targeted block actions.
      - Benign IOCs NEVER generate block actions.
      - Phishing lures trigger mailbox sweep & credential reset recommendations.
      - Campaign clusters trigger campaign-wide mailbox sweep actions.
    """
    case = case_service.get_case(db, case_id)
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    # Existing actions for deduplication
    existing_actions = get_case_responses(db, case_id)
    existing_keys = {(a.action_type, a.target.strip().lower()) for a in existing_actions}

    # Extract parsed investigation findings
    primary_inv_payload: dict[str, Any] = {}
    if case.investigation_results:
        inv = case.investigation_results[-1]
        try:
            parsed = json.loads(inv.ai_analysis)
            if isinstance(parsed, dict):
                primary_inv_payload = parsed
        except Exception:
            pass

    email_meta = primary_inv_payload.get("email", {})
    auth_meta = primary_inv_payload.get("authentication", {})
    threat_analysis_meta = primary_inv_payload.get("threat_analysis", {})
    threat_intel_meta = primary_inv_payload.get("threat_intelligence", [])
    geo_hops_meta = primary_inv_payload.get("geo_hops", [])

    new_recommendations: list[ResponseAction] = []
    batch_offset = 0
    now = datetime.now(timezone.utc)

    # 1. Threat Intelligence Observable Recommendations (Malicious IOCs only)
    for obs in threat_intel_meta:
        indicator = str(obs.get("indicator", "")).strip()
        obs_type = str(obs.get("type", "")).lower()
        obs_status = str(obs.get("status", "")).lower()
        confidence = obs.get("confidence", 0)
        source = obs.get("source", "Threat Intelligence")
        reasons = obs.get("reasons", [])

        # Strict Guardrail: Ignore benign or low-risk unknown observables
        if obs_status != "malicious" or not indicator:
            continue

        action_type = None
        if obs_type == "url":
            action_type = "BLOCK_URL"
        elif obs_type in ("domain", "sender_domain"):
            action_type = "BLOCK_DOMAIN"
        elif obs_type == "ip":
            action_type = "BLOCK_IP"

        if action_type and (action_type, indicator.lower()) not in existing_keys:
            r_id = generate_response_id(db, batch_offset)
            batch_offset += 1
            action = ResponseAction(
                response_id=r_id,
                case_id=case.id,
                action_type=action_type,
                target=indicator,
                severity="high" if confidence >= 80 else "medium",
                reason=f"{obs_type.upper()} '{indicator}' classified as MALICIOUS with {confidence}% confidence by {source}.",
                evidence_json=json.dumps([f"Threat Intel Status: {obs_status}", f"Confidence: {confidence}%"] + [str(r) for r in reasons]),
                source=f"Threat Intelligence ({source})",
                status="RECOMMENDED",
                execution_mode="SIMULATION",
                requested_by="Threat Intelligence Engine",
                result_message="",
                created_at=now,
            )
            db.add(action)
            new_recommendations.append(action)
            existing_keys.add((action_type, indicator.lower()))

    # 2. Phishing Lure & Credential Harvesting Recommendations
    verdict = str(case.threat_type or threat_analysis_meta.get("threat_type") or "").lower()
    subject = email_meta.get("subject") or (case.email_artifacts[0].subject if case.email_artifacts else "")
    sender = email_meta.get("from") or (case.email_artifacts[0].sender if case.email_artifacts else "")
    recipient = email_meta.get("to") or (case.email_artifacts[0].recipient if case.email_artifacts else "")

    if "phish" in verdict or "credential" in verdict or "bec" in verdict or threat_analysis_meta.get("confidence_score", 0) >= 60:
        # Action: Search Mailbox
        mb_target = f"Subject: '{subject}' | Sender: '{sender}'" if subject else (sender or "Suspicious Mailbox Sweep")
        if ("SEARCH_MAILBOX", mb_target.lower()) not in existing_keys:
            r_id = generate_response_id(db, batch_offset)
            batch_offset += 1
            action = ResponseAction(
                response_id=r_id,
                case_id=case.id,
                action_type="SEARCH_MAILBOX",
                target=mb_target,
                severity="medium",
                reason="Search enterprise mailboxes for matching phishing indicators, spoofed sender addresses, and subject lines.",
                evidence_json=json.dumps([f"Threat Verdict: {verdict.upper()}", f"Impersonated Sender: {sender}", f"Lure Subject: {subject}"]),
                source="Phishing Detection Engine",
                status="RECOMMENDED",
                execution_mode="SIMULATION",
                requested_by="SOC Detection Engine",
                result_message="",
                created_at=now,
            )
            db.add(action)
            new_recommendations.append(action)
            existing_keys.add(("SEARCH_MAILBOX", mb_target.lower()))

        # Action: Reset Credential Recommendation
        cred_target = recipient or "Targeted Recipient Account"
        if ("RESET_CREDENTIAL_RECOMMENDATION", cred_target.lower()) not in existing_keys and recipient:
            r_id = generate_response_id(db, batch_offset)
            batch_offset += 1
            action = ResponseAction(
                response_id=r_id,
                case_id=case.id,
                action_type="RESET_CREDENTIAL_RECOMMENDATION",
                target=cred_target,
                severity="high",
                reason=f"Recipient '{recipient}' was targeted by an active credential harvesting threat. Recommend mandatory password reset.",
                evidence_json=json.dumps([f"Recipient: {recipient}", "Credential Harvesting Vector Flagged"]),
                source="AI Investigation Panel",
                status="RECOMMENDED",
                execution_mode="SIMULATION",
                requested_by="AI Investigation Panel",
                result_message="",
                created_at=now,
            )
            db.add(action)
            new_recommendations.append(action)
            existing_keys.add(("RESET_CREDENTIAL_RECOMMENDATION", cred_target.lower()))

    # 3. Campaign Correlation Recommendations
    if case.campaigns:
        for camp in case.campaigns:
            camp_target = f"Campaign {camp.name} ({camp.campaign_id})"
            if ("SEARCH_MAILBOX", camp_target.lower()) not in existing_keys:
                r_id = generate_response_id(db, batch_offset)
                batch_offset += 1
                action = ResponseAction(
                    response_id=r_id,
                    case_id=case.id,
                    action_type="SEARCH_MAILBOX",
                    target=camp_target,
                    severity="critical",
                    reason=f"Correlated attack campaign '{camp.name}' detected with {camp.shared_ioc_count} shared indicators. Conduct enterprise-wide mailbox sweep.",
                    evidence_json=json.dumps([f"Campaign ID: {camp.campaign_id}", f"Confidence: {camp.confidence}%", f"Shared IOCs: {camp.shared_ioc_count}"]),
                    source="Campaign Correlation Engine",
                    status="RECOMMENDED",
                    execution_mode="SIMULATION",
                    requested_by="Campaign Detection Service",
                    result_message="",
                    created_at=now,
                )
                db.add(action)
                new_recommendations.append(action)
                existing_keys.add(("SEARCH_MAILBOX", camp_target.lower()))

    # 4. Protocol Authentication Failure Quarantine
    if auth_meta.get("spf") == "fail" or auth_meta.get("dmarc") == "fail":
        filename = case.email_artifacts[0].filename if case.email_artifacts else "inbound_message.eml"
        if ("ISOLATE_ARTIFACT", filename.lower()) not in existing_keys:
            r_id = generate_response_id(db, batch_offset)
            batch_offset += 1
            action = ResponseAction(
                response_id=r_id,
                case_id=case.id,
                action_type="ISOLATE_ARTIFACT",
                target=filename,
                severity="medium",
                reason="Inbound message failed SPF/DMARC authentication. Recommend automated quarantine isolation.",
                evidence_json=json.dumps([f"SPF: {auth_meta.get('spf')}", f"DMARC: {auth_meta.get('dmarc')}"]),
                source="Protocol Authentication Audit",
                status="RECOMMENDED",
                execution_mode="SIMULATION",
                requested_by="Auth Verification Engine",
                result_message="",
                created_at=now,
            )
            db.add(action)
            new_recommendations.append(action)
            existing_keys.add(("ISOLATE_ARTIFACT", filename.lower()))

    if new_recommendations:
        db.commit()
        for action in new_recommendations:
            db.refresh(action)

        # Log timeline event
        case_service.add_timeline_event(
            db,
            case_id=case.id,
            event_type="RESPONSE_RECOMMENDED",
            description=f"Generated {len(new_recommendations)} controlled incident response recommendation(s).",
            event_metadata={
                "action_count": len(new_recommendations),
                "actions": [a.action_type for a in new_recommendations],
            },
        )

    return get_case_responses(db, case_id)


def approve_response_action(
    db: Session,
    case_id: int,
    response_id: str,
    approved_by: str = "SOC Lead Analyst",
) -> ResponseAction:
    """Transitions a response action to APPROVED status through the analyst approval gate."""
    action = get_response(db, response_id)
    if not action or action.case_id != case_id:
        raise ValueError(f"Response action '{response_id}' for case {case_id} not found.")

    if action.status not in ("RECOMMENDED", "PENDING_APPROVAL"):
        raise ValueError(f"Cannot approve action in status '{action.status}'. Must be in RECOMMENDED or PENDING_APPROVAL state.")

    now = datetime.now(timezone.utc)
    action.status = "APPROVED"
    action.approved_by = approved_by
    action.approved_at = now
    db.commit()
    db.refresh(action)

    # Timeline event
    case_service.add_timeline_event(
        db,
        case_id=case_id,
        event_type="RESPONSE_APPROVED",
        description=f"Response action '{action.response_id}' ({action.action_type} -> {action.target}) APPROVED by {approved_by}.",
        event_metadata={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "approved_by": approved_by,
        },
    )

    # Evidence Ledger sealing
    evidence_ledger.record_ledger_entry(
        db,
        case_id=case_id,
        entry_type="RESPONSE_ACTION",
        data_or_hash={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "status": "APPROVED",
            "approved_by": approved_by,
            "timestamp": now.isoformat(),
        },
        reference_id=action.response_id,
        metadata={"status": "APPROVED", "action_type": action.action_type, "target": action.target},
    )

    return action


def reject_response_action(
    db: Session,
    case_id: int,
    response_id: str,
    rejected_by: str = "SOC Lead Analyst",
    reason: str = "Action rejected by SOC analyst.",
) -> ResponseAction:
    """Rejects a response action, preventing any subsequent execution."""
    action = get_response(db, response_id)
    if not action or action.case_id != case_id:
        raise ValueError(f"Response action '{response_id}' for case {case_id} not found.")

    if action.status in ("EXECUTED", "EXECUTING"):
        raise ValueError(f"Cannot reject action in status '{action.status}'. Action has already been executed.")

    now = datetime.now(timezone.utc)
    action.status = "REJECTED"
    action.approved_by = rejected_by
    action.result = "EXECUTION_BLOCKED"
    action.result_message = reason
    db.commit()
    db.refresh(action)

    # Timeline event
    case_service.add_timeline_event(
        db,
        case_id=case_id,
        event_type="RESPONSE_REJECTED",
        description=f"Response action '{action.response_id}' ({action.action_type}) REJECTED by {rejected_by}: {reason}",
        event_metadata={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "rejected_by": rejected_by,
            "reason": reason,
        },
    )

    # Evidence Ledger sealing
    evidence_ledger.record_ledger_entry(
        db,
        case_id=case_id,
        entry_type="RESPONSE_ACTION",
        data_or_hash={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "status": "REJECTED",
            "reason": reason,
            "timestamp": now.isoformat(),
        },
        reference_id=action.response_id,
        metadata={"status": "REJECTED", "action_type": action.action_type, "target": action.target},
    )

    return action


def execute_response_action(
    db: Session,
    case_id: int,
    response_id: str,
    executed_by: str = "SOC Automation Engine",
) -> ResponseAction:
    """
    Executes an approved response action strictly in SIMULATION mode.
    Enforces the approval guardrail: ONLY APPROVED actions may execute.
    """
    action = get_response(db, response_id)
    if not action or action.case_id != case_id:
        raise ValueError(f"Response action '{response_id}' for case {case_id} not found.")

    # Strict Approval Guardrail
    if action.status != "APPROVED":
        raise ValueError(f"Execution blocked: Response action '{response_id}' is in status '{action.status}'. Explicit analyst approval required.")

    now = datetime.now(timezone.utc)
    action.status = "EXECUTING"

    # Safe Simulation Execution Engine
    simulated_messages = {
        "BLOCK_DOMAIN": f"SIMULATION: Perimeter DNS sinkhole & SEG block rule generated for domain '{action.target}'.",
        "BLOCK_IP": f"SIMULATION: Boundary firewall egress drop rule generated for IP '{action.target}'.",
        "BLOCK_URL": f"SIMULATION: Web Proxy URL filter / SEG mail quarantine rule generated for '{action.target}'.",
        "SEARCH_MAILBOX": f"SIMULATION: Enterprise mailbox discovery query dispatched: {action.target}.",
        "ISOLATE_ARTIFACT": f"SIMULATION: Perimeter quarantine vault isolation executed for artifact '{action.target}'.",
        "FLAG_USER": f"SIMULATION: High-risk monitoring policy attached to targeted identity '{action.target}'.",
        "RESET_CREDENTIAL_RECOMMENDATION": f"SIMULATION: IAM password reset / session revocation ticket dispatched for '{action.target}'.",
    }

    result_msg = simulated_messages.get(
        action.action_type,
        f"SIMULATION: Response action {action.action_type} executed successfully on target {action.target}."
    )

    action.status = "EXECUTED"
    action.execution_mode = "SIMULATION"
    action.result = "SIMULATED_SUCCESS"
    action.result_message = result_msg
    action.executed_at = now
    db.commit()
    db.refresh(action)

    # Timeline Event
    case_service.add_timeline_event(
        db,
        case_id=case_id,
        event_type="RESPONSE_EXECUTED",
        description=f"Response action '{action.response_id}' ({action.action_type}) EXECUTED in SIMULATION mode: {action.target}",
        event_metadata={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "execution_mode": "SIMULATION",
            "result": "SIMULATED_SUCCESS",
            "executed_by": executed_by,
        },
    )

    # Evidence Ledger Sealing
    evidence_ledger.record_ledger_entry(
        db,
        case_id=case_id,
        entry_type="RESPONSE_ACTION",
        data_or_hash={
            "response_id": action.response_id,
            "action_type": action.action_type,
            "target": action.target,
            "status": "EXECUTED",
            "execution_mode": "SIMULATION",
            "result": "SIMULATED_SUCCESS",
            "timestamp": now.isoformat(),
        },
        reference_id=action.response_id,
        metadata={"status": "EXECUTED", "action_type": action.action_type, "target": action.target, "mode": "SIMULATION"},
    )

    return action
