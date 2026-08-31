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


class ThreatAnalysis(BaseModel):
    classification: str = "Safe"
    confidence_score: int = Field(default=0, ge=0, le=100)
    mitre_attack_mapping: str = "T1566"
    social_engineering_techniques: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    explanation: str = "No analysis available."
    recommended_action: str = "Review the message before taking action."
    risk_level: str = "safe"
    deterministic_assessment: PhishingScanResponse | None = None


class AttackGraph(BaseModel):
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    links: list[dict[str, Any]] = Field(default_factory=list)


class InvestigationResponse(BaseModel):
    email: EmailData
    authentication: AuthenticationStatus
    geo_hops: list[GeoHop] = Field(default_factory=list)
    threat_analysis: ThreatAnalysis
    attack_graph: AttackGraph
    evidence_hash: str


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
