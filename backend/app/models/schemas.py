from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EmailData(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_address: str = Field(default="", alias="from")
    to_address: str = Field(default="", alias="to")
    subject: str = ""
    date: str = ""
    message_id: str = ""
    body: str = ""
    reply_to: str = ""
    urls: list[str] = Field(default_factory=list)
    link_mismatches: list[str] = Field(default_factory=list)
    received_headers: list[str] = Field(default_factory=list)
    authentication_results: str = ""


class AuthenticationStatus(BaseModel):
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"


class GeoHop(BaseModel):
    ip: str
    country: str = "Unknown"
    city: str = "Unknown"
    isp: str = "Unknown"
    asn: str = "Unknown"


class AttackTechnique(BaseModel):
    id: str = "T1566"
    name: str = "Phishing"
    reason: str = ""


class ThreatAnalysis(BaseModel):
    # Existing backwards-compatible fields
    classification: str = "Safe"
    confidence_score: int = Field(default=0, ge=0, le=100)
    mitre_attack_mapping: str = "T1566"
    social_engineering_techniques: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    explanation: str = "No analysis available."
    recommended_action: str = "Review the message before taking action."
    risk_level: str = "safe"
    deterministic_assessment: PhishingScanResponse | None = None
    ai_used: bool = False

    # Case 3 Structured AI Investigation Panel fields
    threat_type: str = "Unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    summary: str = ""
    reasons: list[str] = Field(default_factory=list)
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    analyst_conclusion: str = ""


class AttackGraph(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    links: list[dict[str, Any]] = Field(default_factory=list)


class ThreatIntelResult(BaseModel):
    indicator: str
    type: Literal["url", "domain", "ip", "email", "message_id"]
    status: Literal["malicious", "suspicious", "benign", "unknown", "unavailable"] = "unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    source: str = "Local Analysis"
    first_seen: str | None = None
    last_seen: str | None = None
    reputation: str | None = None
    country: str | None = None
    asn: str | None = None
    isp: str | None = None
    categories: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class InvestigationResponse(BaseModel):
    email: EmailData
    authentication: AuthenticationStatus
    geo_hops: list[GeoHop] = Field(default_factory=list)
    threat_analysis: ThreatAnalysis
    attack_graph: AttackGraph
    evidence_hash: str
    threat_intelligence: list[ThreatIntelResult] = Field(default_factory=list)


class RiskFinding(BaseModel):
    code: str
    category: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    detail: str
    weight: int = Field(ge=0, le=100)
    evidence: str = ""


class URLAssessment(BaseModel):
    original: str
    normalized: str
    host: str = ""
    risk_score: int = Field(ge=0, le=100)
    risk_level: Literal["safe", "low", "medium", "high", "critical"]


class PhishingScanRequest(BaseModel):
    """Input for local phishing analysis; at least one URL or text field is required."""

    url: str = Field(default="", max_length=8192)
    urls: list[str] = Field(default_factory=list, max_length=20)
    text: str = Field(default="", max_length=100_000)
    sender: str = Field(default="", max_length=1024)
    reply_to: str = Field(default="", max_length=1024)
    authentication: AuthenticationStatus = Field(default_factory=AuthenticationStatus)

    @model_validator(mode="after")
    def require_scannable_content(self) -> PhishingScanRequest:
        if not self.url.strip() and not self.urls and not self.text.strip():
            raise ValueError("Provide a URL, a list of URLs, or message text to analyze.")
        return self


class PhishingScanResponse(BaseModel):
    model_version: str
    classification: Literal["benign", "suspicious", "phishing"]
    risk_level: Literal["safe", "low", "medium", "high", "critical"]
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    urls: list[URLAssessment] = Field(default_factory=list)
    indicators: list[RiskFinding] = Field(default_factory=list)
    summary: str
    recommended_action: str


# ── Case Management Schemas ──────────────────────────────────

class CaseCreate(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=10000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    threat_type: str = Field(default="phishing", max_length=64)


class CaseUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=10000)
    status: Literal["open", "in_progress", "closed"] | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    threat_type: str | None = Field(default=None, max_length=64)


class EmailArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    filename: str
    sha256: str
    subject: str
    sender: str
    recipient: str
    created_at: str


class InvestigationResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    risk_score: int
    risk_level: str
    verdict: str
    ai_analysis: str
    created_at: str


class AnalystNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=10000)


class AnalystNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    note: str
    created_at: str


class TimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    event_type: str
    description: str
    timestamp: str
    event_metadata: str


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_number: str
    title: str
    description: str
    status: str
    severity: str
    threat_type: str
    created_at: str
    updated_at: str
    email_artifacts: list[EmailArtifactResponse] = Field(default_factory=list)
    investigation_results: list[InvestigationResultResponse] = Field(default_factory=list)
    analyst_notes: list[AnalystNoteResponse] = Field(default_factory=list)
    timeline_events: list[TimelineEventResponse] = Field(default_factory=list)


# ── Timeline Summary Schema ──────────────────────────────────

class TimelineEventDetail(BaseModel):
    """Single serialised timeline event for the /timeline endpoint."""
    id: int
    case_id: int
    event_type: str
    description: str
    timestamp: str
    event_metadata: str


class TimelineSummaryResponse(BaseModel):
    """Full timeline summary returned by GET /api/v1/cases/{case_id}/timeline."""
    case_id: int
    case_number: str
    total_events: int
    first_event_at: str | None = None
    last_event_at: str | None = None
    total_duration_ms: int | None = None
    events: list[TimelineEventDetail] = Field(default_factory=list)


# ── Campaign Detection Schemas ───────────────────────────────

class CampaignEmailMember(BaseModel):
    artifact_id: int
    case_id: int | None = None
    subject: str = ""
    sender: str = ""
    recipient: str = ""
    date: str = ""
    risk_score: int = 0
    threat_type: str = "Unknown"
    related_ioc_count: int = 0


class SharedIndicator(BaseModel):
    indicator: str
    type: Literal["url", "domain", "ip", "sender_domain", "reply_to", "asn"]
    emails_count: int
    emails_seen: list[int] = Field(default_factory=list)
    status: Literal["malicious", "suspicious", "benign", "unknown", "unavailable"] = "unknown"
    confidence: int = Field(default=0, ge=0, le=100)
    source: str = "Threat Intelligence"
    reasons: list[str] = Field(default_factory=list)


class CorrelationSignal(BaseModel):
    signal: str
    weight: int
    detail: str


class CorrelationPair(BaseModel):
    source_email_id: int
    target_email_id: int
    score: int = Field(ge=0, le=100)
    signals: list[CorrelationSignal] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class CampaignProfile(BaseModel):
    id: int | None = None
    campaign_id: str
    case_id: int | None = None
    name: str
    status: str = "detected"
    confidence: int = Field(default=0, ge=0, le=100)
    threat_type: str = "Credential Phishing"
    email_count: int = 0
    shared_ioc_count: int = 0
    shared_infrastructure_count: int = 0
    emails: list[CampaignEmailMember] = Field(default_factory=list)
    shared_indicators: list[SharedIndicator] = Field(default_factory=list)
    correlations: list[CorrelationPair] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    ai_summary: str = ""
    attack_graph: AttackGraph = Field(default_factory=AttackGraph)
    created_at: str = ""
    updated_at: str = ""


class CampaignDetectionResponse(BaseModel):
    status: Literal["completed", "insufficient_data", "no_campaigns_detected"]
    emails_analyzed: int = 0
    campaigns_detected: int = 0
    high_confidence_campaigns: int = 0
    shared_iocs: int = 0
    campaigns: list[CampaignProfile] = Field(default_factory=list)
    message: str = ""


class CampaignListItem(BaseModel):
    id: int
    campaign_id: str
    case_id: int | None = None
    name: str
    status: str
    threat_type: str
    confidence: int
    email_count: int
    shared_ioc_count: int
    shared_infrastructure_count: int
    created_at: str
    updated_at: str


class CampaignListResponse(BaseModel):
    total_campaigns: int
    high_confidence_count: int
    total_emails_correlated: int
    total_shared_iocs: int
    campaigns: list[CampaignListItem] = Field(default_factory=list)


# ── Evidence Ledger Schemas ──────────────────────────────────

class LedgerEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    sequence_number: int
    entry_type: str
    reference_id: str = ""
    data_hash: str
    previous_hash: str
    entry_hash: str
    metadata_json: str = "{}"
    timestamp: str


class LedgerVerificationResponse(BaseModel):
    case_id: int
    status: Literal["intact", "tampered", "empty", "not_found"]
    is_valid: bool
    total_entries: int
    verified_entries: int
    first_break_at: int | None = None
    break_reason: str | None = None
    merkle_root: str | None = None
    latest_entry_hash: str | None = None
    message: str = ""


class LedgerSummaryResponse(BaseModel):
    case_id: int
    case_number: str
    total_entries: int
    is_valid: bool
    status: str
    merkle_root: str
    latest_entry_hash: str | None = None
    entries: list[LedgerEntryResponse] = Field(default_factory=list)


# ── DFIR Report Schemas ──────────────────────────────────────

class ReportCreate(BaseModel):
    report_type: Literal["DFIR_FULL", "EXECUTIVE_SUMMARY"] = "DFIR_FULL"
    title: str | None = Field(default=None, max_length=255)


class ReportListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    report_id: str
    report_type: str
    title: str
    report_hash: str
    ledger_status: str
    generated_at: str
    created_at: str


class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    case_id: int
    report_id: str
    report_type: str
    title: str
    report_hash: str
    ledger_status: str
    generated_at: str
    created_at: str
    content: dict[str, Any] = Field(default_factory=dict)


class ReportListResponse(BaseModel):
    total_reports: int
    reports: list[ReportListItem] = Field(default_factory=list)


# ── Incident Response & SOC Automation Schemas ───────────────

class ResponseActionCreate(BaseModel):
    action_type: Literal[
        "BLOCK_DOMAIN",
        "BLOCK_IP",
        "BLOCK_URL",
        "SEARCH_MAILBOX",
        "ISOLATE_ARTIFACT",
        "FLAG_USER",
        "RESET_CREDENTIAL_RECOMMENDATION",
    ]
    target: str = Field(min_length=1, max_length=512)
    reason: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    evidence: list[str] = Field(default_factory=list)
    source: str = Field(default="SOC Analyst", max_length=128)


class ResponseActionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    response_id: str
    case_id: int
    action_type: str
    target: str
    severity: str
    reason: str
    evidence: list[str] = Field(default_factory=list)
    source: str
    status: str
    execution_mode: str
    requested_by: str
    approved_by: str | None = None
    result: str | None = None
    result_message: str
    created_at: str
    approved_at: str | None = None
    executed_at: str | None = None


class ResponseActionListResponse(BaseModel):
    case_id: int
    total_actions: int
    recommended_count: int
    pending_approval_count: int
    approved_count: int
    executed_count: int
    rejected_count: int
    actions: list[ResponseActionResponse] = Field(default_factory=list)


class ResponseActionApproveRequest(BaseModel):
    approved_by: str = Field(default="SOC Lead Analyst", max_length=128)
    comments: str = Field(default="", max_length=1000)


class ResponseActionRejectRequest(BaseModel):
    rejected_by: str = Field(default="SOC Lead Analyst", max_length=128)
    reason: str = Field(default="Action rejected by SOC analyst.", max_length=1000)


class ResponseActionExecuteRequest(BaseModel):
    executed_by: str = Field(default="SOC Automation Engine", max_length=128)






