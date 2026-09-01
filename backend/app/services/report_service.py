from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Case, Report
from app.services import case_service, evidence_ledger


def generate_report_number(db: Session) -> str:
    """Generate a sequential report identifier: RPT-YYYY-XXXX."""
    year = datetime.now(timezone.utc).year
    prefix = f"RPT-{year}-"

    stmt = select(Report.report_id).where(Report.report_id.like(f"{prefix}%"))
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


def canonical_report_hash(content: dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 digest of the canonical report structure."""
    canonical = json.dumps(
        content,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _derive_recommendations(
    threat_analysis: dict[str, Any],
    threat_intelligence: list[dict[str, Any]],
    auth_status: dict[str, Any],
    campaigns: list[dict[str, Any]],
    is_ledger_intact: bool,
) -> list[str]:
    """Generates actionable SOC remediation playbooks directly derived from actual case findings."""
    recs: list[str] = []

    # 1. Threat analysis specific recommendations
    existing_recs = threat_analysis.get("recommendations", [])
    if isinstance(existing_recs, list) and existing_recs:
        for r in existing_recs:
            if r and r not in recs:
                recs.append(str(r))

    # 2. Malicious observables
    malicious_urls = [i["indicator"] for i in threat_intelligence if i.get("type") == "url" and i.get("status") == "malicious"]
    malicious_domains = [i["indicator"] for i in threat_intelligence if i.get("type") in ("domain", "sender_domain") and i.get("status") == "malicious"]
    malicious_ips = [i["indicator"] for i in threat_intelligence if i.get("type") == "ip" and i.get("status") == "malicious"]

    if malicious_urls or malicious_domains:
        recs.append("Add flagged malicious domains and URLs to the perimeter Secure Email Gateway (SEG) and Web Proxy blocklists.")
    if malicious_ips:
        recs.append("Implement boundary firewall / egress filter drops for identified malicious relay IPs.")

    # 3. Credential Phishing / BEC
    threat_type = str(threat_analysis.get("threat_type", "")).lower()
    if "phish" in threat_type or "credential" in threat_type or "bec" in threat_type:
        recs.append("Initiate immediate password reset and revoke active session tokens for potentially compromised recipient accounts.")
        recs.append("Enforce hardware-backed FIDO2 / MFA challenges for all impacted identity endpoints.")

    # 4. Authentication failures
    if auth_status.get("spf") == "fail" or auth_status.get("dmarc") == "fail":
        recs.append("Investigate spoofing activity; review sender domain DMARC policy enforcement (p=reject / p=quarantine).")

    # 5. Campaign Presence
    if campaigns:
        recs.append(f"Perform enterprise-wide mailbox sweep for correlated attack campaign identifiers ({len(campaigns)} active cluster(s)).")

    # 6. Integrity
    if not is_ledger_intact:
        recs.append("Evidence integrity anomaly detected: conduct forensic database audit and review chain-of-custody signatures.")

    if not recs:
        recs.append("Perform routine message review through an independent, out-of-band communication channel.")

    return recs


def build_report_data(
    db: Session,
    case_id: int,
    report_type: str = "DFIR_FULL",
    title: str = "",
) -> dict[str, Any]:
    """Collects actual Case 1–8 persisted data into an 11-section structured dictionary."""
    case = case_service.get_case(db, case_id)
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    # Verify Evidence Ledger Integrity
    ledger_verification = evidence_ledger.verify_case_ledger(db, case_id)
    is_ledger_intact = ledger_verification.get("is_valid", False)
    ledger_status = "VERIFIED" if is_ledger_intact else ("TAMPERED" if ledger_verification.get("status") == "tampered" else "UNVERIFIED")

    # Extract parsed investigation results
    primary_inv_payload: dict[str, Any] = {}
    verdict = case.threat_type or "phishing"
    risk_score = 0
    risk_level = case.severity or "medium"

    if case.investigation_results:
        inv = case.investigation_results[-1]  # Latest investigation result
        risk_score = inv.risk_score
        risk_level = inv.risk_level
        verdict = inv.verdict
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
    attack_graph_meta = primary_inv_payload.get("attack_graph", {})
    evidence_hash_meta = primary_inv_payload.get("evidence_hash") or (case.email_artifacts[0].sha256 if case.email_artifacts else "N/A")

    # Threat Intelligence IOC breakdown
    total_iocs = len(threat_intel_meta)
    malicious_iocs = [i for i in threat_intel_meta if i.get("status") == "malicious"]
    suspicious_iocs = [i for i in threat_intel_meta if i.get("status") == "suspicious"]
    benign_iocs = [i for i in threat_intel_meta if i.get("status") == "benign"]
    unknown_iocs = [i for i in threat_intel_meta if i.get("status") in ("unknown", "unavailable")]

    # Artifacts collection
    artifacts_data = [
        {
            "id": art.id,
            "filename": art.filename,
            "sha256": art.sha256,
            "subject": art.subject,
            "sender": art.sender,
            "recipient": art.recipient,
            "created_at": art.created_at.isoformat() if art.created_at else "",
        }
        for art in case.email_artifacts
    ]

    # Campaigns collection
    campaigns_data = [
        {
            "campaign_id": camp.campaign_id,
            "name": camp.name,
            "status": camp.status,
            "threat_type": camp.threat_type,
            "confidence": camp.confidence,
            "email_count": camp.email_count,
            "shared_ioc_count": camp.shared_ioc_count,
            "shared_infrastructure_count": camp.shared_infrastructure_count,
            "created_at": camp.created_at.isoformat() if camp.created_at else "",
        }
        for camp in case.campaigns
    ]

    # Timeline events collection
    timeline_summary = case_service.get_case_timeline(db, case_id)
    timeline_events = timeline_summary.get("events", []) if timeline_summary else []

    # Analyst notes collection
    analyst_notes_data = [
        {
            "id": note.id,
            "author": "SOC Lead Analyst",
            "note": note.note,
            "created_at": note.created_at.isoformat() if note.created_at else "",
        }
        for note in case.analyst_notes
    ]

    # Attack graph summary
    nodes = attack_graph_meta.get("nodes", [])
    links = attack_graph_meta.get("links", [])
    graph_summary = {
        "total_nodes": len(nodes),
        "total_links": len(links),
        "node_types": list(dict.fromkeys(n.get("type", "unknown") for n in nodes)),
        "malicious_nodes": [n.get("name") or n.get("id") for n in nodes if n.get("status") == "malicious"],
        "suspicious_nodes": [n.get("name") or n.get("id") for n in nodes if n.get("status") == "suspicious"],
        "relationships_detected": list(dict.fromkeys(l.get("label", "CONNECTED") for l in links)),
    }

    # Dynamic response recommendations
    recommendations = _derive_recommendations(
        threat_analysis=threat_analysis_meta,
        threat_intelligence=threat_intel_meta,
        auth_status=auth_meta,
        campaigns=campaigns_data,
        is_ledger_intact=is_ledger_intact,
    )

    # ── Section 1: Executive Summary ──
    executive_summary = {
        "case_number": case.case_number,
        "case_title": case.title,
        "severity": case.severity.upper(),
        "status": case.status.upper(),
        "threat_type": (threat_analysis_meta.get("threat_type") or verdict).upper(),
        "overall_verdict": verdict.upper(),
        "confidence_score": threat_analysis_meta.get("confidence") or threat_analysis_meta.get("confidence_score") or risk_score,
        "risk_level": risk_level.upper(),
        "summary_narrative": (
            threat_analysis_meta.get("summary")
            or threat_analysis_meta.get("explanation")
            or f"Automated forensic triage classified this incident as {verdict.upper()} with {risk_score}% risk confidence."
        ),
        "evidence_artifact_count": len(artifacts_data),
        "total_iocs_evaluated": total_iocs,
        "malicious_iocs_count": len(malicious_iocs),
        "suspicious_iocs_count": len(suspicious_iocs),
        "campaign_status": f"Correlated with {len(campaigns_data)} Threat Campaign(s)" if campaigns_data else "No correlated campaign identified.",
        "evidence_integrity_status": ledger_status,
        "merkle_root": ledger_verification.get("merkle_root") or "0" * 64,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    # ── Section 2: Incident Details ──
    incident_details = {
        "case_id": case.id,
        "case_number": case.case_number,
        "title": case.title,
        "description": case.description,
        "severity": case.severity,
        "status": case.status,
        "threat_type": case.threat_type,
        "created_at": case.created_at.isoformat() if case.created_at else "",
        "updated_at": case.updated_at.isoformat() if case.updated_at else "",
    }

    # ── Section 3: Email Forensics ──
    email_forensics = {
        "artifact_count": len(artifacts_data),
        "primary_message_id": email_meta.get("message_id") or (artifacts_data[0]["filename"] if artifacts_data else "N/A"),
        "sender": email_meta.get("from") or (artifacts_data[0]["sender"] if artifacts_data else "N/A"),
        "recipient": email_meta.get("to") or (artifacts_data[0]["recipient"] if artifacts_data else "N/A"),
        "reply_to": email_meta.get("reply_to") or "None",
        "subject": email_meta.get("subject") or (artifacts_data[0]["subject"] if artifacts_data else "N/A"),
        "date": email_meta.get("date") or "N/A",
        "evidence_sha256": evidence_hash_meta,
        "received_headers_count": len(email_meta.get("received_headers", [])),
        "relay_hops_count": len(geo_hops_meta),
        "relay_hops": geo_hops_meta,
        "artifacts": artifacts_data,
    }

    # ── Section 4: Authentication Analysis ──
    auth_analysis = {
        "spf": auth_meta.get("spf", "none").upper(),
        "dkim": auth_meta.get("dkim", "none").upper(),
        "dmarc": auth_meta.get("dmarc", "none").upper(),
        "is_aligned": auth_meta.get("spf") == "pass" and auth_meta.get("dkim") == "pass",
        "authentication_results_header": email_meta.get("authentication_results", "None"),
        "analysis_notes": (
            "All email authentication protocols validated successfully."
            if auth_meta.get("spf") == "pass" and auth_meta.get("dmarc") == "pass"
            else "Email authentication failure detected: Potential domain impersonation or spoofed relay route."
        ),
    }

    # ── Section 5: Threat Intelligence ──
    threat_intelligence = {
        "total_indicators": total_iocs,
        "malicious_count": len(malicious_iocs),
        "suspicious_count": len(suspicious_iocs),
        "benign_count": len(benign_iocs),
        "unknown_count": len(unknown_iocs),
        "indicators": threat_intel_meta,
    }

    # ── Section 6: Attack Graph ──
    attack_graph = graph_summary

    # ── Section 7: Campaign Analysis ──
    campaign_analysis = {
        "campaigns_detected": len(campaigns_data),
        "campaign_summary": "Correlated Attack Campaign(s) Identified" if campaigns_data else "No correlated campaign identified.",
        "campaigns": campaigns_data,
    }

    # ── Section 8: Forensic Timeline ──
    forensic_timeline = {
        "total_events": len(timeline_events),
        "first_event_at": timeline_summary.get("first_event_at"),
        "last_event_at": timeline_summary.get("last_event_at"),
        "events": timeline_events,
    }

    # ── Section 9: Evidence Integrity ──
    evidence_integrity = {
        "evidence_sha256": evidence_hash_meta,
        "ledger_status": ledger_status,
        "ledger_engine": "Tamper-Evident Cryptographic Evidence Ledger (RFC 6234 / SHA-256)",
        "total_chained_blocks": ledger_verification.get("total_entries", 0),
        "verified_blocks": ledger_verification.get("verified_entries", 0),
        "merkle_root": ledger_verification.get("merkle_root") or "0" * 64,
        "latest_block_hash": ledger_verification.get("latest_entry_hash"),
        "first_integrity_break": ledger_verification.get("first_break_at"),
        "verification_message": ledger_verification.get("message", ""),
    }

    # ── Section 10: Analyst Notes ──
    analyst_notes = {
        "total_notes": len(analyst_notes_data),
        "notes": analyst_notes_data,
    }

    # ── Section 11: Response Recommendations ──
    response_recommendations = {
        "total_actions": len(recommendations),
        "recommendations": recommendations,
    }

    # ── Section 12: Incident Response Actions (Case 10) ──
    import json as _json
    response_actions_data = []
    for ra in getattr(case, 'response_actions', []):
        evidence_list = []
        try:
            evidence_list = _json.loads(ra.evidence_json) if ra.evidence_json else []
        except Exception:
            pass
        response_actions_data.append({
            "response_id": ra.response_id,
            "action_type": ra.action_type,
            "target": ra.target,
            "severity": ra.severity,
            "reason": ra.reason,
            "evidence": evidence_list,
            "source": ra.source,
            "status": ra.status,
            "execution_mode": ra.execution_mode,
            "result": ra.result or "",
            "result_message": ra.result_message,
            "requested_by": ra.requested_by,
            "approved_by": ra.approved_by or "",
            "created_at": ra.created_at.isoformat() if ra.created_at else "",
            "approved_at": ra.approved_at.isoformat() if ra.approved_at else "",
            "executed_at": ra.executed_at.isoformat() if ra.executed_at else "",
        })

    executed_actions = [a for a in response_actions_data if a["status"] == "EXECUTED"]
    approved_actions = [a for a in response_actions_data if a["status"] == "APPROVED"]
    rejected_actions = [a for a in response_actions_data if a["status"] == "REJECTED"]
    recommended_actions = [a for a in response_actions_data if a["status"] == "RECOMMENDED"]

    response_actions_summary = {
        "total_response_actions": len(response_actions_data),
        "executed_count": len(executed_actions),
        "approved_count": len(approved_actions),
        "rejected_count": len(rejected_actions),
        "recommended_count": len(recommended_actions),
        "simulation_disclaimer": "All executed actions were performed in SIMULATION mode. No production systems were modified.",
        "actions": response_actions_data,
    }

    if report_type == "EXECUTIVE_SUMMARY":
        return {
            "report_type": "EXECUTIVE_SUMMARY",
            "case_number": case.case_number,
            "title": title or f"Executive Summary — {case.title}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": executive_summary,
            "incident_details": incident_details,
            "threat_intelligence_summary": {
                "total_iocs": total_iocs,
                "malicious": len(malicious_iocs),
                "suspicious": len(suspicious_iocs),
            },
            "campaign_status": campaign_analysis["campaign_summary"],
            "evidence_integrity": evidence_integrity,
            "response_recommendations": response_recommendations,
            "response_actions_summary": response_actions_summary,
        }

    # Return Full DFIR Report
    return {
        "report_type": "DFIR_FULL",
        "case_number": case.case_number,
        "title": title or f"DFIR Incident Investigation Report — {case.title}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": executive_summary,
        "incident_details": incident_details,
        "email_forensics": email_forensics,
        "authentication_analysis": auth_analysis,
        "threat_intelligence": threat_intelligence,
        "attack_graph_summary": attack_graph,
        "campaign_analysis": campaign_analysis,
        "forensic_timeline": forensic_timeline,
        "evidence_integrity": evidence_integrity,
        "analyst_notes": analyst_notes,
        "response_recommendations": response_recommendations,
        "response_actions_summary": response_actions_summary,
    }


def create_case_report(
    db: Session,
    case_id: int,
    report_type: str = "DFIR_FULL",
    title: str = "",
) -> Report:
    """
    Generates a structured DFIR report or Executive Summary, calculates its canonical SHA-256 hash,
    records a REPORT_GENERATED timeline event, seals a REPORT_GENERATED block in the Evidence Ledger,
    and persists the Report entity in SQLite.
    """
    case = case_service.get_case(db, case_id)
    if not case:
        raise ValueError(f"Case with ID {case_id} not found.")

    report_id = generate_report_number(db)
    report_type_normalized = "EXECUTIVE_SUMMARY" if report_type.upper() == "EXECUTIVE_SUMMARY" else "DFIR_FULL"
    report_title = title.strip() or f"{'Executive Summary' if report_type_normalized == 'EXECUTIVE_SUMMARY' else 'DFIR Incident Report'} — {case.title}"

    # Build the full structured content
    content_dict = build_report_data(
        db=db,
        case_id=case_id,
        report_type=report_type_normalized,
        title=report_title,
    )

    # Compute deterministic canonical report hash
    rep_hash = canonical_report_hash(content_dict)
    content_dict["report_id"] = report_id
    content_dict["report_hash"] = rep_hash

    content_json = json.dumps(content_dict, ensure_ascii=False)
    now = datetime.now(timezone.utc)
    ledger_status = content_dict.get("executive_summary", {}).get("evidence_integrity_status", "VERIFIED")

    # Persist Report row
    report = Report(
        case_id=case.id,
        report_id=report_id,
        report_type=report_type_normalized,
        title=report_title,
        content=content_json,
        report_hash=rep_hash,
        ledger_status=ledger_status,
        generated_at=now,
        created_at=now,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # Record REPORT_GENERATED event in timeline
    case_service.add_timeline_event(
        db,
        case_id=case.id,
        event_type="REPORT_GENERATED",
        description=f"{report_type_normalized} report '{report.report_id}' generated (SHA-256: {rep_hash[:16]}...).",
        event_metadata={
            "report_id": report.report_id,
            "report_type": report.report_type,
            "report_hash": rep_hash,
            "ledger_status": ledger_status,
            "generated_at": now.isoformat(),
        },
    )

    # Seal REPORT_GENERATED in Evidence Ledger
    evidence_ledger.record_ledger_entry(
        db,
        case_id=case.id,
        entry_type="REPORT_GENERATED",
        data_or_hash=rep_hash,
        reference_id=report.report_id,
        metadata={
            "report_id": report.report_id,
            "report_type": report.report_type,
            "title": report.title,
            "report_hash": rep_hash,
            "ledger_status": ledger_status,
        },
    )

    return report


def get_case_reports(db: Session, case_id: int) -> list[Report]:
    """Retrieve all reports generated for a case ordered by generated_at descending."""
    stmt = select(Report).where(Report.case_id == case_id).order_by(Report.generated_at.desc())
    return list(db.scalars(stmt).all())


def get_report(db: Session, identifier: str | int) -> Report | None:
    """Retrieve a report by primary key ID or unique report_id string."""
    if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
        rep = db.get(Report, int(identifier))
        if rep:
            return rep
    stmt = select(Report).where(Report.report_id == str(identifier))
    return db.scalars(stmt).first()


def render_markdown(report_dict: dict[str, Any]) -> str:
    """Render a structured report dictionary into clean, professional GitHub-flavored Markdown."""
    r_type = report_dict.get("report_type", "DFIR_FULL")
    exec_sum = report_dict.get("executive_summary", {})
    inc_det = report_dict.get("incident_details", {})
    r_id = report_dict.get("report_id", "RPT-PENDING")
    r_hash = report_dict.get("report_hash", "N/A")

    if r_type == "EXECUTIVE_SUMMARY":
        md = f"""# MAILTRACE AI — EXECUTIVE INCIDENT SUMMARY
===================================================================
Report ID       : {r_id}
Case Number     : {exec_sum.get('case_number', 'N/A')}
Generated Date  : {report_dict.get('generated_at', '')}
Incident Verdict: {exec_sum.get('overall_verdict', 'UNKNOWN')} ({exec_sum.get('confidence_score', 0)}% Confidence)
Severity Level  : {exec_sum.get('severity', 'MEDIUM')}
Report SHA-256  : {r_hash}
Ledger Integrity: {exec_sum.get('evidence_integrity_status', 'VERIFIED')}

1. EXECUTIVE OVERVIEW
-------------------------------------------------------------------
{exec_sum.get('summary_narrative', '')}

2. INCIDENT METRICS
-------------------------------------------------------------------
- Evidence Artifacts  : {exec_sum.get('evidence_artifact_count', 0)} file(s)
- IOCs Evaluated      : {exec_sum.get('total_iocs_evaluated', 0)} observables
- Malicious Indicators: {exec_sum.get('malicious_iocs_count', 0)} flagged
- Campaign Status     : {exec_sum.get('campaign_status', 'None')}
- Merkle Tree Root    : {exec_sum.get('merkle_root', '0'*64)}

3. STRATEGIC RESPONSE ACTIONS
-------------------------------------------------------------------
"""
        for idx, rec in enumerate(report_dict.get("response_recommendations", {}).get("recommendations", []), 1):
            md += f"{idx}. {rec}\n"
        md += "\n===================================================================\n"
        md += "Report sealed by MailTrace AI DFIR Platform // SIH26106\n"
        return md

    # Full DFIR Report rendering
    email_for = report_dict.get("email_forensics", {})
    auth_an = report_dict.get("authentication_analysis", {})
    threat_intel = report_dict.get("threat_intelligence", {})
    graph_sum = report_dict.get("attack_graph_summary", {})
    camp_an = report_dict.get("campaign_analysis", {})
    timeline = report_dict.get("forensic_timeline", {})
    integrity = report_dict.get("evidence_integrity", {})
    notes = report_dict.get("analyst_notes", {})

    md = f"""# MAILTRACE AI — DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) REPORT
===================================================================
Report Identifier : {r_id}
Case Reference    : {exec_sum.get('case_number', 'N/A')} ({inc_det.get('title', '')})
Classification    : {exec_sum.get('overall_verdict', 'UNKNOWN')} (Risk Score: {exec_sum.get('confidence_score', 0)}/100)
Severity / Status : {exec_sum.get('severity', 'MEDIUM')} / {exec_sum.get('status', 'OPEN')}
Report Hash SHA256: {r_hash}
Evidence Seal Hash: {integrity.get('evidence_sha256', 'N/A')}
Ledger Chain State: {integrity.get('ledger_status', 'VERIFIED')} ({integrity.get('total_chained_blocks', 0)} Blocks Chained)
Merkle Tree Root  : {integrity.get('merkle_root', '0'*64)}
Generation Date   : {report_dict.get('generated_at', '')}

1. EXECUTIVE SUMMARY
-------------------------------------------------------------------
{exec_sum.get('summary_narrative', '')}

2. INCIDENT SPECIFICATIONS
-------------------------------------------------------------------
- Case ID     : {inc_det.get('case_id', 'N/A')}
- Case Number : {inc_det.get('case_number', 'N/A')}
- Title       : {inc_det.get('title', 'N/A')}
- Threat Type : {inc_det.get('threat_type', 'N/A')}
- Description : {inc_det.get('description', 'N/A')}
- Created At  : {inc_det.get('created_at', 'N/A')}

3. EMAIL FORENSIC EVIDENCE ARTIFACTS
-------------------------------------------------------------------
- Sender (From)      : {email_for.get('sender', 'N/A')}
- Recipient (To)     : {email_for.get('recipient', 'N/A')}
- Subject Line       : {email_for.get('subject', 'N/A')}
- Unique Message-ID  : {email_for.get('primary_message_id', 'N/A')}
- Message Timestamp  : {email_for.get('date', 'N/A')}
- Evidence SHA-256   : {email_for.get('evidence_sha256', 'N/A')}
- Total Relay Hops   : {email_for.get('relay_hops_count', 0)}

"""
    if email_for.get("relay_hops"):
        md += "External Relay Hop Traversal:\n"
        for hop in email_for.get("relay_hops", []):
            md += f"  • {hop.get('ip')} — {hop.get('city', 'Unknown')}, {hop.get('country', 'Unknown')} (ISP: {hop.get('isp', 'Unknown')})\n"
        md += "\n"

    md += f"""4. EMAIL PROTOCOL AUTHENTICATION AUDIT
-------------------------------------------------------------------
- SPF (RFC 7208)   : {auth_an.get('spf', 'NONE')}
- DKIM (RFC 6376)  : {auth_an.get('dkim', 'NONE')}
- DMARC (RFC 7489) : {auth_an.get('dmarc', 'NONE')}
- Alignment Status : {'ALIGNED' if auth_an.get('is_aligned') else 'MISALIGNED / FAILED'}
- Protocol Details : {auth_an.get('analysis_notes', '')}

5. THREAT INTELLIGENCE OBSERVABLES & IOCs
-------------------------------------------------------------------
Total Observables Evaluated: {threat_intel.get('total_indicators', 0)}
- Malicious  : {threat_intel.get('malicious_count', 0)}
- Suspicious : {threat_intel.get('suspicious_count', 0)}
- Benign     : {threat_intel.get('benign_count', 0)}

Evaluated Indicators:
"""
    for obs in threat_intel.get("indicators", []):
        md += f"  • [{obs.get('status', 'unknown').upper()}] ({obs.get('type')}) {obs.get('indicator')} (Confidence: {obs.get('confidence', 0)}%)\n"

    md += f"""
6. ATTACK GRAPH TOPOLOGY
-------------------------------------------------------------------
- Total Graph Nodes : {graph_sum.get('total_nodes', 0)}
- Total Graph Links : {graph_sum.get('total_links', 0)}
- Node Types        : {', '.join(graph_sum.get('node_types', []))}
- Malicious Nodes   : {', '.join(graph_sum.get('malicious_nodes', [])) or 'None'}
- Relationships     : {', '.join(graph_sum.get('relationships_detected', []))}

7. CAMPAIGN CORRELATION ANALYSIS
-------------------------------------------------------------------
- Campaign Status   : {camp_an.get('campaign_summary', 'No campaign detected.')}
"""
    for camp in camp_an.get("campaigns", []):
        md += f"  • Campaign '{camp.get('name')}' ({camp.get('campaign_id')}) — Confidence: {camp.get('confidence')}%, Shared IOCs: {camp.get('shared_ioc_count')}\n"

    md += f"""
8. FORENSIC CHRONOLOGICAL TIMELINE
-------------------------------------------------------------------
Total Milestone Events: {timeline.get('total_events', 0)}
"""
    for evt in timeline.get("events", []):
        md += f"  • [{evt.get('timestamp')}] {evt.get('event_type')}: {evt.get('description')}\n"

    md += f"""
9. EVIDENCE INTEGRITY & CHAIN OF CUSTODY
-------------------------------------------------------------------
- Architecture  : {integrity.get('ledger_engine')}
- Ledger Status : {integrity.get('ledger_status')}
- Total Blocks  : {integrity.get('total_chained_blocks')} chained blocks
- Merkle Root   : {integrity.get('merkle_root')}
- Latest Block  : {integrity.get('latest_block_hash')}

10. SOC ANALYST REMARKS
-------------------------------------------------------------------
"""
    if notes.get("notes"):
        for n in notes.get("notes", []):
            md += f"  • [{n.get('created_at')}] ({n.get('author')}): {n.get('note')}\n"
    else:
        md += "  • Automated DFIR triage completed. No additional analyst notes appended.\n"

    md += """
11. INCIDENT RESPONSE PLAYBOOK & RECOMMENDATIONS
-------------------------------------------------------------------
"""
    for idx, rec in enumerate(report_dict.get("response_recommendations", {}).get("recommendations", []), 1):
        md += f"{idx}. {rec}\n"

    # Section 12: Response Actions (Case 10)
    resp_summary = report_dict.get("response_actions_summary", {})
    if resp_summary.get("total_response_actions", 0) > 0:
        md += f"""
12. CONTROLLED INCIDENT RESPONSE ACTIONS
-------------------------------------------------------------------
Total Response Actions : {resp_summary.get('total_response_actions', 0)}
Executed (Simulation)  : {resp_summary.get('executed_count', 0)}
Approved (Pending Exec): {resp_summary.get('approved_count', 0)}
Rejected               : {resp_summary.get('rejected_count', 0)}
Recommended            : {resp_summary.get('recommended_count', 0)}

⚠ SIMULATION DISCLAIMER: {resp_summary.get('simulation_disclaimer', 'All actions were simulated.')}
"""
        for ra in resp_summary.get("actions", []):
            md += f"  • [{ra.get('status')}] {ra.get('action_type')} → {ra.get('target')} (Mode: {ra.get('execution_mode')}, Result: {ra.get('result') or 'PENDING'})\n"
        md += "\n"

    md += """
===================================================================
Digital Forensics & Incident Response (DFIR) Report // MailTrace AI
Certified Tamper-Evident Cryptographic Ledger Seal Active
"""
    return md
