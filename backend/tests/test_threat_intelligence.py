"""Tests for Case 4: Threat Intelligence & IOC Enrichment."""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.threat_intelligence import (
    ExternalThreatIntelProvider,
    LocalThreatIntelProvider,
    ThreatIntelligenceService,
    defang_ioc,
    is_public_ipv4,
    normalize_domain,
    normalize_url,
    refang_ioc,
)

SAMPLE_EML_INTEL = """From: "Security Operations" <alert@login-targetcorp-auth.com>
To: target.user@target.com
Subject: Action Required: MFA Token Reset
Date: Tue, 01 Sep 2026 10:00:00 +0000
Message-ID: <intel-001@login-targetcorp-auth.com>
Received: from mail.login-targetcorp-auth.com (198.51.100.22) by mx.target.com; Tue, 01 Sep 2026 10:00:00 +0000
Authentication-Results: mx.target.com; spf=fail; dkim=none; dmarc=fail

Please verify your credentials at https://login-targetcorp-auth.com/auth/login?session=9821a
"""


class ThreatIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

        def _override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.local_provider = LocalThreatIntelProvider()

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)

    # 1. URL intelligence normalization & defanging/refanging
    def test_url_normalization_and_defanging(self) -> None:
        raw = "hxxps://login-evil[.]com/auth/login"
        refanged = refang_ioc(raw)
        self.assertEqual(refanged, "https://login-evil.com/auth/login")

        defanged = defang_ioc("https://evil.com/payload")
        self.assertEqual(defanged, "hxxps://evil[.]com/payload")

    # 2. Domain normalization
    def test_domain_normalization(self) -> None:
        self.assertEqual(normalize_domain("user@evil-domain.com"), "evil-domain.com")
        self.assertEqual(normalize_domain("https://sub.evil-domain[.]com:8080/path"), "sub.evil-domain.com")

    # 3. IPv4 intelligence (public vs private check)
    def test_ipv4_classification(self) -> None:
        self.assertTrue(is_public_ipv4("8.8.8.8"))
        self.assertFalse(is_public_ipv4("192.168.1.1"))
        self.assertFalse(is_public_ipv4("127.0.0.1"))
        self.assertFalse(is_public_ipv4("invalid.ip"))

    # 4. Local suspicious-domain detection (lookalikes / typosquatting / TLDs)
    def test_local_suspicious_domain_detection(self) -> None:
        res = asyncio.run(self.local_provider.lookup("login-targetcorp-auth.com", "domain"))
        self.assertIn(res["status"], ("malicious", "suspicious"))
        self.assertGreaterEqual(res["confidence"], 50)
        self.assertTrue(len(res["reasons"]) >= 1)

    # 5. Local suspicious-URL detection (credential lures / IP hosts)
    def test_local_suspicious_url_detection(self) -> None:
        res_ip_url = asyncio.run(self.local_provider.lookup("http://198.51.100.22/auth/login", "url"))
        self.assertIn(res_ip_url["status"], ("malicious", "suspicious"))
        self.assertGreaterEqual(res_ip_url["confidence"], 60)
        self.assertIn("URL destination points directly to raw numeric IP address", res_ip_url["reasons"])

    # 6. Unknown reputation when no external provider exists
    def test_unknown_reputation_when_no_evidence(self) -> None:
        res = asyncio.run(self.local_provider.lookup("<random-id@example.org>", "message_id"))
        self.assertEqual(res["status"], "unknown")
        self.assertLessEqual(res["confidence"], 30)

    # 7. External provider timeout / exception safety
    def test_external_provider_timeout_and_safe_fallback(self) -> None:
        ext_provider = ExternalThreatIntelProvider()
        # If API key not set, lookup returns None cleanly without error
        res = asyncio.run(ext_provider.lookup("8.8.8.8", "ip"))
        self.assertIsNone(res)

    # 8. Multiple IOC correlation and deduplication
    def test_multiple_ioc_correlation_and_deduplication(self) -> None:
        service = ThreatIntelligenceService()
        email_data = {
            "from": "alert@evil.com",
            "reply_to": "alert@evil.com",  # Duplicate domain
            "urls": ["http://evil.com/auth", "http://evil.com/auth"],  # Duplicate URL
            "received_headers": ["from mail.evil.com (8.8.8.8) by mx.target.com"],
            "message_id": "<msg-001@evil.com>",
        }
        enriched = asyncio.run(service.enrich_all(email_data))
        # Ensure no exact duplicate (indicator, type) pairs exist
        seen = set()
        for item in enriched:
            key = (item["indicator"].lower(), item["type"])
            self.assertNotIn(key, seen)
            seen.add(key)
        self.assertTrue(len(enriched) >= 3)

    # 9. API investigation endpoint returns threat_intelligence in response
    def test_api_investigation_returns_threat_intelligence(self) -> None:
        resp = self.client.post(
            "/api/v1/investigate",
            files={"file": ("test.eml", SAMPLE_EML_INTEL.encode(), "message/rfc822")},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("threat_intelligence", data)
        intel = data["threat_intelligence"]
        self.assertTrue(len(intel) >= 2)
        # Check structure
        first = intel[0]
        self.assertIn("indicator", first)
        self.assertIn("type", first)
        self.assertIn("status", first)
        self.assertIn("confidence", first)
        self.assertIn("source", first)

    # 10. Threat intelligence timeline event emitted
    def test_threat_intelligence_timeline_event_emitted(self) -> None:
        case_id = self.client.post("/api/v1/cases", json={"title": "Intel Timeline Test"}).json()["id"]
        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_INTEL.encode(), "message/rfc822")},
        )
        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("THREAT_INTELLIGENCE_COMPLETED", event_types)

    # 11. Malicious status only when corroborated by evidence
    def test_malicious_status_criteria(self) -> None:
        res = asyncio.run(self.local_provider.lookup(
            "http://login-targetcorp-auth.com/auth/login?session=token",
            "url",
            context={"phishing_assessment": {"indicators": [{"title": "Credential Harvester", "category": "credential_lure"}]}},
        ))
        self.assertEqual(res["status"], "malicious")
        self.assertGreaterEqual(res["confidence"], 70)

    # 12. Benign status for private internal IPs
    def test_benign_status_for_internal_ip(self) -> None:
        res = asyncio.run(self.local_provider.lookup("10.0.4.12", "ip"))
        self.assertEqual(res["status"], "benign")
        self.assertEqual(res["confidence"], 80)

    # 13. Attack graph nodes enriched with threat intelligence properties
    def test_attack_graph_enriched_with_intelligence(self) -> None:
        resp = self.client.post(
            "/api/v1/investigate",
            files={"file": ("test.eml", SAMPLE_EML_INTEL.encode(), "message/rfc822")},
        )
        self.assertEqual(resp.status_code, 200)
        graph = resp.json()["attack_graph"]
        nodes = graph["nodes"]
        sender_node = next((n for n in nodes if n.get("type") == "sender"), None)
        self.assertIsNotNone(sender_node)
        self.assertIn("status", sender_node)


if __name__ == "__main__":
    unittest.main()
