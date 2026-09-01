"""Threat Intelligence & IOC Enrichment Service.

Provides IOC normalization, defanging/refanging, local deterministic threat intelligence,
provider abstraction for optional external reputation sources, and IOC correlation.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any
from urllib.parse import unquote, urlsplit

import httpx

logger = logging.getLogger(__name__)

# Pattern for IPv4
_IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")

# Suspicious TLDs
_SUSPICIOUS_TLDS = {
    "buzz", "cam", "click", "country", "gq", "icu", "info", "link",
    "live", "monster", "online", "rest", "shop", "site", "support",
    "top", "vip", "work", "xyz", "zip"
}

# Known shorteners
_SHORTENERS = {
    "bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy",
    "rebrand.ly", "shorturl.at", "t.co", "tiny.cc", "tinyurl.com"
}


def defang_ioc(value: str) -> str:
    """Defangs a URL, IP, or domain for safe reporting."""
    if not value:
        return value
    val = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return re.sub(r"\.(?=[a-zA-Z0-9_-])", "[.]", val)


def refang_ioc(value: str) -> str:
    """Restores defanged indicators (e.g. hxxp://, [.], (.), [dot]) to standard form."""
    if not value:
        return value
    val = value.strip()
    if val.lower().startswith("hxxps://"):
        val = "https://" + val[8:]
    elif val.lower().startswith("hxxp://"):
        val = "http://" + val[7:]
    val = val.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".").replace("{.}", ".")
    val = val.replace("[:]", ":")
    return val


def normalize_domain(domain_or_url: str) -> str:
    """Extracts and lowercases the hostname/domain from a string."""
    cleaned = refang_ioc(domain_or_url).strip()
    if "@" in cleaned and not cleaned.startswith(("http://", "https://")):
        cleaned = cleaned.split("@")[-1]
    if "://" in cleaned:
        try:
            cleaned = urlsplit(cleaned).netloc or cleaned
        except ValueError:
            pass
    cleaned = cleaned.split(":")[0].strip("[]/").lower()
    return cleaned


def normalize_url(raw_url: str) -> str:
    """Cleans and standardizes a URL for intelligence lookup."""
    url = refang_ioc(raw_url).strip()
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def is_public_ipv4(ip_str: str) -> bool:
    """Checks whether an IP is a valid public global IPv4 address."""
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return ip.is_global and not ip.is_private and not ip.is_loopback
    except (ipaddress.AddressValueError, ValueError):
        return False


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @abstractmethod
    async def lookup(
        self,
        indicator: str,
        ioc_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Looks up an indicator and returns threat intelligence metadata or None."""
        pass


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Local, deterministic threat intelligence provider.

    Correlates static indicators, domain features, URL anomalies, and detector findings.
    """

    async def lookup(
        self,
        indicator: str,
        ioc_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = context or {}
        reasons: list[str] = []
        categories: list[str] = []
        status = "unknown"
        confidence = 10
        country: str | None = None
        asn: str | None = None
        isp: str | None = None

        if ioc_type == "url":
            refanged_url = refang_ioc(indicator)
            try:
                parsed = urlsplit(refanged_url)
                host = parsed.netloc.split(":")[0].lower()
                path = unquote(parsed.path).lower()
                query = unquote(parsed.query).lower()
            except ValueError:
                host = ""
                path = ""
                query = ""

            # Check if host is raw IP
            if _IPV4_RE.match(host):
                reasons.append("URL destination points directly to raw numeric IP address")
                categories.append("ip_destination")
                confidence += 35

            # Check shorteners
            if host in _SHORTENERS:
                reasons.append("URL utilizes link shortening service to mask true destination")
                categories.append("url_shortener")
                confidence += 25

            # Check host brand typosquatting
            typo_patterns = [
                r"login-", r"auth-", r"security-", r"targetcorp", r"ce0", r"mfa-", r"support-",
                r"sbi-", r"sbi-alert", r"hdfc-", r"icici-", r"axis-", r"paytm-", r"phonepee",
                r"upi-", r"upi-kyc", r"epfo-", r"epfo-member", r"incometax-", r"payroll-",
            ]
            if any(re.search(pat, host) for pat in typo_patterns):
                reasons.append("URL host exhibits lookalike or brand typosquatting characteristics")
                categories.append("brand_lookalike")
                confidence += 30

            # Check credential solicitation paths
            cred_keywords = [
                "login", "signin", "verify", "auth", "mfa", "token", "password",
                "session", "secure", "update", "kyc", "upi", "pan", "aadhaar",
                "uan", "epfo", "release", "track",
            ]
            if any(k in path or k in query for k in cred_keywords):
                reasons.append("URL path contains credential or authentication solicitation patterns")
                categories.append("credential_lure")
                confidence += 30

            # Match detector findings if provided
            phishing_assessment = context.get("phishing_assessment", {})
            for finding in phishing_assessment.get("indicators", []):
                if isinstance(finding, dict):
                    ev = str(finding.get("evidence", "")).lower()
                    cat = str(finding.get("category", "")).lower()
                    if host in ev or refanged_url.lower() in ev or cat in ("url_structure", "url_intent", "credential_lure"):
                        reasons.append(finding.get("title", "Suspicious link behavior"))
                        categories.append(finding.get("category", "url_risk"))
                        confidence += 20

            # Assign status
            if confidence >= 70:
                status = "malicious" if any("credential" in c or "mfa" in r.lower() or "brand_lookalike" in c for c, r in zip(categories, reasons)) else "suspicious"
            elif confidence >= 40:
                status = "suspicious"
            else:
                status = "unknown" if not reasons else "suspicious"

        elif ioc_type == "domain":
            domain = normalize_domain(indicator)
            tld = domain.split(".")[-1] if "." in domain else ""

            if tld in _SUSPICIOUS_TLDS:
                reasons.append(f"Domain registered under high-risk TLD (.{tld})")
                categories.append("suspicious_tld")
                confidence += 30

            if domain.startswith("xn--") or ".xn--" in domain:
                reasons.append("Domain utilizes internationalized punycode lookalike encoding")
                categories.append("punycode_homoglyph")
                confidence += 40

            # Brand typo heuristics (e.g. zeros substituting O, lookalikes)
            typo_patterns = [
                r"login-", r"auth-", r"security-", r"targetcorp", r"ce0", r"mfa-", r"support-",
                r"sbi-", r"sbi-alert", r"hdfc-", r"icici-", r"axis-", r"paytm-", r"phonepee",
                r"upi-", r"upi-kyc", r"epfo-", r"epfo-member", r"incometax-", r"payroll-",
            ]
            if any(re.search(pat, domain) for pat in typo_patterns):
                reasons.append("Domain exhibits lookalike or brand typosquatting characteristics")
                categories.append("brand_lookalike")
                confidence += 45

            phishing_assessment = context.get("phishing_assessment", {})
            for finding in phishing_assessment.get("indicators", []):
                if isinstance(finding, dict) and finding.get("category") in ("brand_impersonation", "sender_identity"):
                    reasons.append(finding.get("title", "Identity anomaly"))
                    categories.append(finding.get("category", "impersonation"))
                    confidence += 25

            if confidence >= 70:
                status = "malicious" if "brand_lookalike" in categories else "suspicious"
            elif confidence >= 35 or reasons:
                status = "suspicious"
            else:
                status = "unknown"

        elif ioc_type == "ip":
            ip_str = indicator.strip()
            is_global = is_public_ipv4(ip_str)

            # Check GeoIP hops
            geo_hops = context.get("geo_hops", [])
            matched_hop = next((h for h in geo_hops if h.get("ip") == ip_str), None)
            if matched_hop:
                country = matched_hop.get("country")
                asn = matched_hop.get("asn")
                isp = matched_hop.get("isp")
                reasons.append(f"Observed relay IP in {country or 'Unknown'} ({isp or asn or 'Unknown ASN'})")
                confidence = 50

            if is_global:
                categories.append("public_relay_ip")
                status = "suspicious" if context.get("auth_fail") else "benign" if context.get("auth_pass") else "unknown"
                confidence = 65 if context.get("auth_fail") else 40
            else:
                categories.append("internal_private_ip")
                reasons.append("Private RFC 1918 / internal local address")
                status = "benign"
                confidence = 80

        elif ioc_type in ("email", "message_id"):
            status = "unknown"
            confidence = 20
            if ioc_type == "email":
                reasons.append("Envelope address observable")
            else:
                reasons.append("Message tracking header identifier")

        confidence = max(0, min(100, confidence))
        reasons = list(dict.fromkeys(reasons))
        categories = list(dict.fromkeys(categories))

        return {
            "indicator": indicator,
            "type": ioc_type,
            "status": status,
            "confidence": confidence,
            "source": "Local Analysis",
            "first_seen": None,
            "last_seen": None,
            "reputation": "Malicious" if status == "malicious" else "Suspicious" if status == "suspicious" else "Benign" if status == "benign" else "Unknown",
            "country": country,
            "asn": asn,
            "isp": isp,
            "categories": categories,
            "reasons": reasons,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


class ExternalThreatIntelProvider(ThreatIntelProvider):
    """Optional external threat intelligence provider hook (e.g. VirusTotal/AbuseIPDB).

    Operates strictly if API keys are configured, with graceful timeouts and fallback.
    """

    def __init__(self) -> None:
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

    async def lookup(
        self,
        indicator: str,
        ioc_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if not self.vt_api_key and not self.abuseipdb_api_key:
            return None

        # Safe external query stub with strict 2.0s timeout and complete exception safety
        try:
            if ioc_type == "ip" and self.abuseipdb_api_key:
                async with httpx.AsyncClient(timeout=2.0) as client:
                    resp = await client.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": indicator, "maxAgeInDays": "90"},
                        headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        score = int(data.get("abuseConfidenceScore", 0))
                        status = "malicious" if score >= 75 else "suspicious" if score >= 25 else "benign"
                        return {
                            "indicator": indicator,
                            "type": "ip",
                            "status": status,
                            "confidence": score,
                            "source": "AbuseIPDB",
                            "first_seen": None,
                            "last_seen": data.get("lastReportedAt"),
                            "reputation": f"Abuse Score: {score}%",
                            "country": data.get("countryCode"),
                            "asn": str(data.get("asn")),
                            "isp": data.get("isp"),
                            "categories": ["external_reputation"],
                            "reasons": [f"AbuseIPDB confidence score: {score}% with {data.get('totalReports', 0)} report(s)"],
                            "checked_at": datetime.now(timezone.utc).isoformat(),
                        }
        except Exception as exc:
            logger.warning("External threat intel lookup timed out or failed (%s)", type(exc).__name__)
        return None


class ThreatIntelligenceService:
    """Coordinates IOC extraction, deduplication, threat intelligence enrichment, and correlation."""

    def __init__(self) -> None:
        self.local_provider = LocalThreatIntelProvider()
        self.external_provider = ExternalThreatIntelProvider()

    async def enrich_all(
        self,
        email_data: dict[str, Any],
        phishing_assessment: dict[str, Any] | None = None,
        geo_hops: list[dict[str, Any]] | None = None,
        authentication: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        geo_hops = geo_hops or []
        authentication = authentication or {}
        auth_fail = any(v != "pass" for v in authentication.values())
        auth_pass = all(v == "pass" for v in authentication.values()) if authentication else False

        # 1. Collect and deduplicate raw IOCs
        iocs: list[tuple[str, str]] = []  # (indicator, type)

        # URLs
        for raw_url in email_data.get("urls", []):
            if raw_url and raw_url.strip():
                iocs.append((raw_url.strip(), "url"))

        # Domains
        sender_email = _first_email(email_data.get("from", ""))
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        if sender_domain:
            iocs.append((sender_domain, "domain"))

        reply_to_email = _first_email(email_data.get("reply_to", ""))
        reply_to_domain = reply_to_email.split("@")[-1].lower() if "@" in reply_to_email else ""
        if reply_to_domain and reply_to_domain != sender_domain:
            iocs.append((reply_to_domain, "domain"))

        for raw_url in email_data.get("urls", []):
            url_domain = normalize_domain(raw_url)
            if url_domain and url_domain not in (sender_domain, reply_to_domain):
                iocs.append((url_domain, "domain"))

        # IPs from Geo hops and headers
        for hop in geo_hops:
            ip = hop.get("ip")
            if ip:
                iocs.append((ip, "ip"))

        for header in email_data.get("received_headers", []):
            for candidate in _IPV4_RE.findall(header):
                iocs.append((candidate, "ip"))

        # Sender & Message-ID
        if sender_email:
            iocs.append((sender_email, "email"))

        message_id = email_data.get("message_id")
        if message_id:
            iocs.append((message_id.strip(), "message_id"))

        # Deduplicate preserving order
        seen: set[tuple[str, str]] = set()
        unique_iocs: list[tuple[str, str]] = []
        for ind, itype in iocs:
            normalized_key = (ind.lower().strip(), itype)
            if normalized_key not in seen:
                seen.add(normalized_key)
                unique_iocs.append((ind, itype))

        context = {
            "phishing_assessment": phishing_assessment or {},
            "geo_hops": geo_hops,
            "auth_fail": auth_fail,
            "auth_pass": auth_pass,
        }

        # 2. Enrich IOCs via providers
        results: list[dict[str, Any]] = []
        for indicator, ioc_type in unique_iocs:
            # Try external provider if available
            external_res = await self.external_provider.lookup(indicator, ioc_type, context)
            if external_res:
                results.append(external_res)
                continue

            # Fallback to local intelligence provider
            local_res = await self.local_provider.lookup(indicator, ioc_type, context)
            results.append(local_res)

        return results


def _first_email(header_value: str) -> str:
    """Extracts first valid email address from a header value."""
    _, addr = parseaddr(header_value)
    return addr.strip().lower() if addr else header_value.strip().lower()
