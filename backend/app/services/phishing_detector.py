"""Local, explainable phishing detection for URLs and message content.

The detector intentionally never follows or resolves submitted URLs.  That keeps a
scan deterministic and avoids turning the API into an SSRF or attacker-tracking
primitive.  It combines independently useful URL, sender, authentication, and
message signals with a bounded noisy-OR risk model.
"""

from __future__ import annotations

import html
import ipaddress
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit


@dataclass(frozen=True)
class Finding:
    """A single, user-visible contribution to the risk score."""

    code: str
    category: str
    title: str
    detail: str
    weight: int
    evidence: str = ""

    @property
    def severity(self) -> str:
        if self.weight >= 55:
            return "critical"
        if self.weight >= 35:
            return "high"
        if self.weight >= 18:
            return "medium"
        return "low"

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "weight": self.weight,
            "evidence": self.evidence,
        }


class PhishingDetector:
    """Explainable, offline phishing-risk classifier.

    This is a defense-in-depth classifier, not a reputation service.  It is
    deliberately conservative about isolated weak signals such as HTTP or a
    newly fashionable TLD, while combinations of independent signals rapidly
    raise the score.
    """

    MODEL_VERSION = "local-hybrid-1.0"
    MAX_URLS = 20

    _URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"'`]+")
    _INVISIBLE_CHARS = re.compile(r"[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
    _SUSPICIOUS_TLDS = {
        "buzz",
        "cam",
        "click",
        "country",
        "gq",
        "icu",
        "info",
        "link",
        "live",
        "monster",
        "online",
        "rest",
        "shop",
        "site",
        "support",
        "top",
        "vip",
        "work",
        "xyz",
        "zip",
    }
    _SHORTENERS = {
        "bit.ly",
        "buff.ly",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "rb.gy",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tiny.one",
        "tinyurl.com",
    }
    _SUSPICIOUS_PATH_TERMS = {
        "account",
        "auth",
        "billing",
        "confirm",
        "credential",
        "login",
        "password",
        "recover",
        "secure",
        "signin",
        "unlock",
        "update",
        "validate",
        "verify",
        "wallet",
    }
    _BRANDS: dict[str, set[str]] = {
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.in"},
        "apple": {"apple.com", "icloud.com"},
        "bankofamerica": {"bankofamerica.com"},
        "chase": {"chase.com"},
        "coinbase": {"coinbase.com"},
        "docusign": {"docusign.com"},
        "dropbox": {"dropbox.com"},
        "facebook": {"facebook.com", "fb.com", "meta.com"},
        "google": {"google.com", "gmail.com", "googleusercontent.com"},
        "linkedin": {"linkedin.com"},
        "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
        "netflix": {"netflix.com"},
        "okta": {"okta.com"},
        "paypal": {"paypal.com"},
        "stripe": {"stripe.com"},
        "wellsfargo": {"wellsfargo.com"},
    }
    _MULTI_PART_SUFFIXES = {"co.uk", "com.au", "com.br", "co.in", "co.jp", "co.nz", "com.sg"}

    def analyze(
        self,
        *,
        urls: Iterable[str] | None = None,
        message: str = "",
        sender: str = "",
        reply_to: str = "",
        authentication: Mapping[str, str] | None = None,
        link_mismatches: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Return a bounded, explainable assessment without making network calls."""

        candidates = list(urls or []) + self.extract_urls(message)
        unique_urls = self._unique_candidates(candidates)
        findings: list[Finding] = []
        url_assessments: list[dict[str, Any]] = []

        for url in unique_urls:
            normalized, host, url_findings = self._analyze_url(url)
            findings.extend(url_findings)
            url_score = self._score(url_findings)
            url_assessments.append(
                {
                    "original": url,
                    "normalized": normalized,
                    "host": host,
                    "risk_score": url_score,
                    "risk_level": self._risk_level(url_score),
                }
            )

        findings.extend(self._analyze_message(message))
        findings.extend(self._analyze_link_mismatches(link_mismatches or []))
        findings.extend(self._analyze_sender(sender, reply_to))
        findings.extend(self._analyze_authentication(authentication or {}))
        findings = self._deduplicate_findings(findings)

        risk_score = self._score(findings)
        risk_level = self._risk_level(risk_score)
        classification = self._classification(risk_score)
        indicators = [finding.as_dict() for finding in sorted(findings, key=lambda item: item.weight, reverse=True)]

        return {
            "model_version": self.MODEL_VERSION,
            "classification": classification,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "confidence": self._confidence(findings, risk_score),
            "urls": url_assessments,
            "indicators": indicators,
            "summary": self._summary(classification, risk_score, findings, len(unique_urls)),
            "recommended_action": self._recommended_action(risk_level),
        }

    def extract_urls(self, text: str) -> list[str]:
        """Extract normal and commonly defanged URLs from untrusted text."""

        if not text:
            return []
        normalized = self._defang(text)
        return [match.group(0).rstrip(".,;:!?)]}>'\"") for match in self._URL_PATTERN.finditer(normalized)]

    def _analyze_url(self, raw_url: str) -> tuple[str, str, list[Finding]]:
        original = str(raw_url or "").strip()
        prepared = self._prepare_url(original)
        findings: list[Finding] = []

        try:
            split = urlsplit(prepared)
            host = (split.hostname or "").rstrip(".").lower()
        except ValueError:
            return prepared, "", [
                Finding(
                    "malformed-url",
                    "url_structure",
                    "Malformed URL",
                    "The URL cannot be parsed safely and may be intentionally malformed.",
                    35,
                    original[:160],
                )
            ]

        if not host:
            return prepared, "", [
                Finding(
                    "missing-host",
                    "url_structure",
                    "URL has no destination host",
                    "The supplied link does not contain a valid destination host.",
                    35,
                    original[:160],
                )
            ]

        ascii_host = self._ascii_host(host)
        unicode_host = self._unicode_host(ascii_host)
        normalized = self._normalized_url(split, ascii_host)
        registrable_domain = self._registrable_domain(ascii_host)
        path_query = f"{split.path}?{split.query}".lower()

        if self._is_obfuscated(original):
            findings.append(
                Finding(
                    "url-obfuscation",
                    "url_structure",
                    "URL uses obfuscation",
                    "The link used defanging, encoded characters, or invisible Unicode that can hide its destination.",
                    28,
                    original[:160],
                )
            )

        if split.username or "@" in split.netloc.rsplit("@", 1)[0]:
            findings.append(
                Finding(
                    "userinfo-in-url",
                    "url_structure",
                    "URL hides its host after @",
                    "Everything before @ is user information; the actual destination is the host after it.",
                    55,
                    ascii_host,
                )
            )

        if self._is_ip_address(ascii_host):
            findings.append(
                Finding(
                    "ip-address-host",
                    "url_structure",
                    "Link targets an IP address",
                    "Credential pages normally use a named domain; raw IP destinations are commonly used to evade domain checks.",
                    45,
                    ascii_host,
                )
            )

        if "xn--" in ascii_host or self._has_mixed_scripts(unicode_host):
            findings.append(
                Finding(
                    "lookalike-domain",
                    "domain_identity",
                    "Possible lookalike domain",
                    "The hostname uses internationalized or mixed-script characters that can resemble another brand.",
                    45,
                    unicode_host,
                )
            )

        if ascii_host in self._SHORTENERS:
            findings.append(
                Finding(
                    "url-shortener",
                    "url_structure",
                    "Shortened link hides its final destination",
                    "This detector does not resolve short links because following them can expose the scanner or recipient.",
                    25,
                    ascii_host,
                )
            )

        labels = [label for label in ascii_host.split(".") if label]
        if len(labels) >= 5:
            findings.append(
                Finding(
                    "excessive-subdomains",
                    "domain_identity",
                    "Excessive subdomain depth",
                    "Deep subdomains can make a malicious registrable domain look like a trusted brand.",
                    16,
                    ascii_host,
                )
            )

        if len(ascii_host) > 63 or (labels and self._shannon_entropy(max(labels, key=len)) >= 3.65):
            findings.append(
                Finding(
                    "randomized-hostname",
                    "domain_identity",
                    "Unusually randomized hostname",
                    "The host is unusually long or high-entropy, a pattern often used in disposable phishing infrastructure.",
                    14,
                    ascii_host,
                )
            )

        if labels and labels[-1] in self._SUSPICIOUS_TLDS:
            findings.append(
                Finding(
                    "high-abuse-tld",
                    "domain_reputation",
                    "High-abuse top-level domain",
                    "This top-level domain is frequently seen in commodity phishing campaigns. It is not harmful by itself.",
                    16,
                    labels[-1],
                )
            )

        if split.scheme == "http":
            findings.append(
                Finding(
                    "unencrypted-link",
                    "transport",
                    "Link does not use HTTPS",
                    "The destination uses unencrypted HTTP, so credentials or page content could be altered in transit.",
                    10,
                    normalized,
                )
            )

        try:
            port = split.port
        except ValueError:
            port = None
            findings.append(
                Finding(
                    "invalid-port",
                    "url_structure",
                    "URL has an invalid port",
                    "An invalid port is often a sign of deliberately malformed link construction.",
                    25,
                    original[:160],
                )
            )
        if port is not None and port not in {80, 443}:
            findings.append(
                Finding(
                    "nonstandard-port",
                    "transport",
                    "Link uses a non-standard port",
                    "Credential phishing kits sometimes use unusual ports to avoid familiar web hosting patterns.",
                    14,
                    str(port),
                )
            )

        if any(term in path_query for term in self._SUSPICIOUS_PATH_TERMS):
            findings.append(
                Finding(
                    "credential-themed-path",
                    "url_intent",
                    "Credential-themed link path",
                    "The path or query requests account access, verification, recovery, or credentials.",
                    17,
                    path_query[:160],
                )
            )

        if re.search(r"(?:redirect|return|target|next|continue|url)=https?%3a|(?:redirect|return|target|next|continue|url)=https?://", path_query):
            findings.append(
                Finding(
                    "redirect-chain",
                    "url_structure",
                    "Link contains a redirect target",
                    "The link contains another web address as a redirect parameter, which can conceal the final destination.",
                    18,
                    path_query[:160],
                )
            )

        if len(normalized) > 180:
            findings.append(
                Finding(
                    "excessive-url-length",
                    "url_structure",
                    "Unusually long URL",
                    "Long links can be used to bury the actual host or add tracking and redirect layers.",
                    9,
                    str(len(normalized)),
                )
            )

        brand = self._brand_in_host(ascii_host)
        if brand and registrable_domain not in self._BRANDS[brand]:
            findings.append(
                Finding(
                    "brand-impersonation-domain",
                    "brand_impersonation",
                    f"{brand.title()} appears in an unrelated domain",
                    "A known brand appears in the hostname, but the registrable domain is not one of that brand's expected domains.",
                    58,
                    registrable_domain,
                )
            )

        return normalized, ascii_host, findings

    def _analyze_message(self, message: str) -> list[Finding]:
        text = unicodedata.normalize("NFKC", message or "")
        lowered = text.lower()
        findings: list[Finding] = []

        if re.search(r"\b(?:urgent|immediately|action required|within \d+ hours?|final (?:notice|warning)|suspend(?:ed)? today)\b", lowered):
            findings.append(
                Finding(
                    "urgency-pressure",
                    "social_engineering",
                    "Urgency or pressure language",
                    "The message pressures the recipient to act before they can independently verify the request.",
                    20,
                )
            )

        if re.search(r"\b(?:account|mailbox|profile|access)\b", lowered) and re.search(
            r"\b(?:disable[ds]?|suspend(?:ed|ing)?|lock(?:ed)?|deactivat(?:e|ed|ion))\b",
            lowered,
        ):
            findings.append(
                Finding(
                    "account-suspension-lure",
                    "social_engineering",
                    "Account suspension threat",
                    "The message threatens loss of account access, a common lure for credential-harvesting campaigns.",
                    27,
                )
            )

        if re.search(r"\b(?:password|passcode|credential|one[- ]?time (?:code|password)|otp|verification code)\b", lowered) and re.search(r"\b(?:enter|share|provide|confirm|verify|submit|reset|sign[ -]?in|log[ -]?in)\b", lowered):
            findings.append(
                Finding(
                    "credential-request",
                    "social_engineering",
                    "Message requests credentials or a verification code",
                    "Legitimate support teams should not ask for passwords, one-time codes, or MFA approvals through an unsolicited message.",
                    38,
                )
            )

        if re.search(r"\b(?:wire transfer|bank transfer|gift ?cards?|crypto(?:currency)?|bitcoin|payment instructions)\b", lowered):
            findings.append(
                Finding(
                    "payment-diversion",
                    "business_email_compromise",
                    "Payment or gift-card request",
                    "Unexpected payment instructions are a common business-email-compromise technique.",
                    34,
                )
            )

        if re.search(r"\b(?:enable (?:content|macros?)|run (?:the )?attachment|open (?:the )?(?:attached )?(?:invoice|document)|download (?:the )?attachment)\b", lowered):
            findings.append(
                Finding(
                    "attachment-lure",
                    "malware_delivery",
                    "Attachment execution lure",
                    "The message encourages opening an attachment or enabling active content.",
                    28,
                )
            )

        if re.search(r"\b(?:keep this confidential|do not call|bypass(?:ing)? (?:normal )?(?:process|approval)|i am (?:the )?(?:ceo|cfo|director))\b", lowered):
            findings.append(
                Finding(
                    "authority-bypass",
                    "business_email_compromise",
                    "Authority or secrecy pressure",
                    "The message tries to bypass normal verification or use executive authority to speed up a request.",
                    26,
                )
            )

        return findings

    @staticmethod
    def _analyze_link_mismatches(mismatches: Iterable[str]) -> list[Finding]:
        findings: list[Finding] = []
        for mismatch in list(dict.fromkeys(str(item) for item in mismatches if item))[:5]:
            findings.append(
                Finding(
                    "visible-link-mismatch",
                    "link_integrity",
                    "Visible link destination differs from its target",
                    "The displayed domain and the link's actual destination are different, which is a common credential-phishing technique.",
                    50,
                    mismatch[:160],
                )
            )
        return findings

    def _analyze_sender(self, sender: str, reply_to: str) -> list[Finding]:
        findings: list[Finding] = []
        display_name, sender_address = parseaddr(sender or "")
        _, reply_address = parseaddr(reply_to or "")
        sender_domain = self._email_domain(sender_address)
        reply_domain = self._email_domain(reply_address)

        if sender_domain and reply_domain and sender_domain != reply_domain:
            findings.append(
                Finding(
                    "reply-to-mismatch",
                    "sender_identity",
                    "Reply-To domain differs from sender domain",
                    "Replies would be redirected to a different domain than the visible sender address.",
                    42,
                    f"{sender_domain} -> {reply_domain}",
                )
            )

        normalized_name = re.sub(r"[^a-z]", "", (display_name or "").lower())
        for brand, domains in self._BRANDS.items():
            if brand in normalized_name and sender_domain and self._registrable_domain(sender_domain) not in domains:
                findings.append(
                    Finding(
                        "brand-impersonation-sender",
                        "brand_impersonation",
                        f"Sender display name impersonates {brand.title()}",
                        "The sender name mentions a known brand, but the sending domain is not an expected brand domain.",
                        48,
                        sender_address,
                    )
                )
                break

        return findings

    @staticmethod
    def _analyze_authentication(authentication: Mapping[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for mechanism, weight in (("dmarc", 25), ("dkim", 18), ("spf", 18)):
            result = str(authentication.get(mechanism, "none")).lower()
            if result in {"fail", "softfail", "permerror", "temperror"}:
                findings.append(
                    Finding(
                        f"{mechanism}-failed",
                        "email_authentication",
                        f"{mechanism.upper()} authentication did not pass",
                        "A failed sender-authentication check is meaningful evidence, but should be interpreted with the message context.",
                        weight,
                        result,
                    )
                )
        return findings

    @classmethod
    def _score(cls, findings: Iterable[Finding]) -> int:
        """Fuse independent categories while capping correlated evidence."""

        categories: dict[str, float] = {}
        strong_signals = 0
        for finding in findings:
            contribution = min(finding.weight / 100, 0.70)
            categories[finding.category] = 1 - (1 - categories.get(finding.category, 0.0)) * (1 - contribution)
            if finding.weight >= 35:
                strong_signals += 1

        if not categories:
            return 0
        combined = 1.0
        for contribution in categories.values():
            combined *= 1 - contribution
        score = round(100 * (1 - combined))
        # Independent high-confidence evidence deserves more weight than a list of weak URL quirks.
        score += min(24, max(0, strong_signals - 1) * 8)
        return max(0, min(100, score))

    @staticmethod
    def _confidence(findings: list[Finding], risk_score: int) -> int:
        if not findings:
            return 62
        category_count = len({finding.category for finding in findings})
        strong_count = sum(finding.weight >= 35 for finding in findings)
        confidence = 60 + category_count * 5 + strong_count * 6 + min(10, risk_score // 20)
        return max(55, min(97, confidence))

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 10:
            return "low"
        return "safe"

    @staticmethod
    def _classification(score: int) -> str:
        if score >= 65:
            return "phishing"
        if score >= 10:
            return "suspicious"
        return "benign"

    @staticmethod
    def _recommended_action(risk_level: str) -> str:
        actions = {
            "critical": "Block or quarantine the message. Do not open the link or attachment; verify the request through a known, independent contact channel.",
            "high": "Do not interact with the message. Independently verify the sender and report the message to security or the service being impersonated.",
            "medium": "Treat the message as suspicious. Verify the sender and destination through a trusted channel before taking any action.",
            "low": "Use caution and inspect the destination independently before entering data or downloading files.",
            "safe": "No high-risk local signals were found. Continue to verify unexpected requests; a low score is not a safety guarantee.",
        }
        return actions[risk_level]

    @staticmethod
    def _summary(classification: str, score: int, findings: list[Finding], url_count: int) -> str:
        if not findings:
            return "No local phishing indicators were found in the supplied content. This result does not include reputation or live-site analysis."
        strongest = sorted(findings, key=lambda item: item.weight, reverse=True)[:2]
        signal_text = "; ".join(finding.title.lower() for finding in strongest)
        noun = "URL" if url_count == 1 else "URLs"
        return f"Local hybrid analysis classified the submission as {classification} (risk {score}/100) after inspecting {url_count} {noun}: {signal_text}."

    @classmethod
    def _prepare_url(cls, value: str) -> str:
        prepared = cls._defang(html.unescape(value)).strip()
        for _ in range(2):
            decoded = unquote(prepared)
            if decoded == prepared:
                break
            prepared = decoded
        prepared = unicodedata.normalize("NFKC", prepared)
        prepared = cls._INVISIBLE_CHARS.sub("", prepared)
        if prepared.lower().startswith("www."):
            prepared = f"https://{prepared}"
        return prepared

    @classmethod
    def _defang(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value or "")
        normalized = re.sub(r"(?i)\bhxxps?\b", lambda match: "https" if match.group(0).lower() == "hxxps" else "http", normalized)
        return normalized.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")

    @classmethod
    def _is_obfuscated(cls, raw_url: str) -> bool:
        raw = raw_url or ""
        return bool(
            re.search(r"(?i)hxxp|\[\.\]|\(\.\)|\[:\]|%[0-9a-f]{2}", raw)
            or bool(cls._INVISIBLE_CHARS.search(raw))
            or unicodedata.normalize("NFKC", raw) != raw
        )

    @staticmethod
    def _ascii_host(host: str) -> str:
        try:
            return host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return host.lower()

    @staticmethod
    def _unicode_host(host: str) -> str:
        try:
            return host.encode("ascii").decode("idna")
        except UnicodeError:
            return host

    @staticmethod
    def _normalized_url(split_result: Any, host: str) -> str:
        scheme = split_result.scheme.lower()
        netloc = host
        try:
            port = split_result.port
        except ValueError:
            port = None
        if port is not None and port not in {80, 443}:
            netloc = f"{host}:{port}"
        return urlunsplit((scheme, netloc, split_result.path or "/", split_result.query, ""))

    @classmethod
    def _registrable_domain(cls, host: str) -> str:
        labels = [label for label in host.lower().split(".") if label]
        if len(labels) < 2:
            return host.lower()
        suffix = ".".join(labels[-2:])
        if suffix in cls._MULTI_PART_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return suffix

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        candidate = host.strip("[]").lower()
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            pass

        if re.fullmatch(r"0x[0-9a-f]+|\d+", candidate):
            base = 16 if candidate.startswith("0x") else 10
            try:
                return 0 <= int(candidate, base) <= 0xFFFFFFFF
            except ValueError:
                return False

        parts = candidate.split(".")
        if len(parts) != 4:
            return False
        try:
            values = [
                int(part, 16) if part.startswith("0x") else int(part, 8) if len(part) > 1 and part.startswith("0") else int(part, 10)
                for part in parts
            ]
        except ValueError:
            return False
        return all(0 <= value <= 255 for value in values)

    @staticmethod
    def _has_mixed_scripts(host: str) -> bool:
        scripts: set[str] = set()
        for character in host:
            if not character.isalpha():
                continue
            name = unicodedata.name(character, "")
            for script in ("LATIN", "CYRILLIC", "GREEK"):
                if script in name:
                    scripts.add(script)
        return len(scripts) > 1

    @classmethod
    def _brand_in_host(cls, host: str) -> str | None:
        normalized = re.sub(r"[^a-z]", "", host.lower())
        for brand in cls._BRANDS:
            if brand in normalized:
                return brand
        return None

    @staticmethod
    def _email_domain(address: str) -> str:
        if "@" not in address:
            return ""
        return address.rsplit("@", 1)[1].lower().rstrip(".")

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = {character: value.count(character) for character in set(value)}
        length = len(value)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @classmethod
    def _unique_candidates(cls, candidates: Iterable[str]) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            cleaned = str(candidate or "").strip()
            if not cleaned:
                continue
            fingerprint = cleaned.lower()
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            unique.append(cleaned)
            if len(unique) == cls.MAX_URLS:
                break
        return unique

    @staticmethod
    def _deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
        deduplicated: dict[tuple[str, str], Finding] = {}
        for finding in findings:
            key = (finding.code, finding.evidence)
            existing = deduplicated.get(key)
            if existing is None or finding.weight > existing.weight:
                deduplicated[key] = finding
        return list(deduplicated.values())
