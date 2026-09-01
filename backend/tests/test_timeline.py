"""
Case 2 — Real Forensic Investigation Timeline Tests.

Tests:
1.  Case creation generates CASE_CREATED event.
2.  Email upload generates EMAIL_UPLOADED event.
3.  Investigation generates granular stage events (EMAIL_PARSED, AUTH_ANALYSIS_COMPLETED, etc.).
4.  GET /timeline returns chronological events.
5.  Timeline belongs to the correct case.
6.  AI skipped when fallback explanation present → AI_ANALYSIS_SKIPPED emitted.
7.  No geo hops → GEOINT_UNAVAILABLE emitted.
8.  Timeline persists to file database (survives session).
9.  GET /timeline returns ISO 8601 timestamps.
10. All existing 13 tests remain unaffected.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime

from fastapi.testclient import TestClient

tmp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp_db_file.close()
os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db_file.name}"

from app.db.base import Base
from app.db.session import engine
from app.main import app


SAMPLE_EML_PHISHING = (
    "From: security-alert@login-targetcorp-auth.com\n"
    "To: employee@target.com\n"
    "Subject: Urgent MFA Verification Required\n"
    "Date: Mon, 31 Aug 2026 14:22:18 +0000\n"
    "Message-ID: <test-timeline-001@domain.com>\n"
    "Authentication-Results: mx.target.com; spf=fail; dkim=fail; dmarc=fail\n"
    "Received: from mail.evil.ru (198.51.100.1) by mx.target.com\n\n"
    "Please verify your credentials at http://login-targetcorp-auth.com/login"
)

SAMPLE_EML_BENIGN = (
    "From: sender@example.com\n"
    "To: recipient@example.com\n"
    "Subject: Quarterly Report\n"
    "Date: Mon, 31 Aug 2026 12:00:00 +0000\n"
    "Message-ID: <benign-001@example.com>\n\n"
    "Hello, please find attached the quarterly report."
)


class TimelineTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls) -> None:
        engine.dispose()
        if os.path.exists(tmp_db_file.name):
            try:
                os.remove(tmp_db_file.name)
            except OSError:
                pass

    def setUp(self) -> None:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)

    # ── Test 1: Case creation generates CASE_CREATED ─────────────────
    def test_case_created_event_generated(self) -> None:
        resp = self.client.post("/api/v1/cases", json={"title": "Timeline Test Case", "severity": "high"})
        self.assertEqual(resp.status_code, 201)
        case_id = resp.json()["id"]

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("CASE_CREATED", event_types)

    # ── Test 2: Email upload generates EMAIL_UPLOADED ─────────────────
    def test_email_uploaded_event_generated(self) -> None:
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "Upload Test Case"}
        ).json()["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_PHISHING.encode(), "message/rfc822")},
        )

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("EMAIL_UPLOADED", event_types)

    # ── Test 3: Investigation generates stage events ──────────────────
    def test_investigation_generates_stage_events(self) -> None:
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "Stage Events Test"}
        ).json()["id"]

        inv = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("phishing.eml", SAMPLE_EML_PHISHING.encode(), "message/rfc822")},
        )
        self.assertEqual(inv.status_code, 200)

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]

        required_stages = [
            "EMAIL_PARSED",
            "AUTH_ANALYSIS_COMPLETED",
            "PHISHING_ANALYSIS_COMPLETED",
            "IOC_EXTRACTION_COMPLETED",
            "ATTACK_GRAPH_GENERATED",
            "EVIDENCE_HASH_GENERATED",
        ]
        for stage in required_stages:
            self.assertIn(stage, event_types, f"Missing stage event: {stage}")

    # ── Test 4: Timeline endpoint returns chronological events ────────
    def test_timeline_chronological_order(self) -> None:
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "Chronological Order Test"}
        ).json()["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_BENIGN.encode(), "message/rfc822")},
        )

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        timestamps = [e["timestamp"] for e in tl["events"]]
        parsed = [datetime.fromisoformat(ts.replace("Z", "+00:00")) for ts in timestamps if ts]
        # Verify that timestamps are non-decreasing (chronological)
        for i in range(1, len(parsed)):
            self.assertGreaterEqual(parsed[i], parsed[i - 1], "Timeline events not in chronological order")

    # ── Test 5: Timeline belongs to the correct case ──────────────────
    def test_timeline_belongs_to_correct_case(self) -> None:
        case_a = self.client.post("/api/v1/cases", json={"title": "Case A"}).json()["id"]
        case_b = self.client.post("/api/v1/cases", json={"title": "Case B"}).json()["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_a},
            files={"file": ("a.eml", SAMPLE_EML_PHISHING.encode(), "message/rfc822")},
        )

        tl_a = self.client.get(f"/api/v1/cases/{case_a}/timeline").json()
        tl_b = self.client.get(f"/api/v1/cases/{case_b}/timeline").json()

        for evt in tl_a["events"]:
            self.assertEqual(evt["case_id"], case_a)

        # Case B only has CASE_CREATED, not investigation stages
        event_types_b = [e["event_type"] for e in tl_b["events"]]
        self.assertNotIn("EMAIL_PARSED", event_types_b)

    # ── Test 6: AI fallback → AI_ANALYSIS_SKIPPED ────────────────────
    def test_ai_fallback_produces_skipped_event(self) -> None:
        """
        When the threat analyzer uses heuristic fallback (Groq unavailable),
        the route should record AI_ANALYSIS_SKIPPED instead of AI_ANALYSIS_COMPLETED.
        We trigger this by patching ThreatAnalyzerService to return a heuristic explanation.
        """
        from unittest.mock import AsyncMock, patch

        fallback_analysis = {
            "classification": "Phishing",
            "confidence_score": 72,
            "risk_level": "high",
            "mitre_attack_mapping": "T1566",
            "social_engineering_techniques": [],
            "suspicious_indicators": ["Suspicious URL"],
            "explanation": "Heuristic fallback: Groq API unavailable.",
            "recommended_action": "Block sender.",
            "deterministic_assessment": None,
        }

        case_id = self.client.post(
            "/api/v1/cases", json={"title": "AI Skipped Test"}
        ).json()["id"]

        with patch(
            "app.services.ai_engine.ThreatAnalyzerService.analyze",
            new_callable=AsyncMock,
            return_value=fallback_analysis,
        ):
            self.client.post(
                "/api/v1/investigate",
                data={"case_id": case_id},
                files={"file": ("test.eml", SAMPLE_EML_PHISHING.encode(), "message/rfc822")},
            )

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("AI_ANALYSIS_SKIPPED", event_types)
        self.assertNotIn("AI_ANALYSIS_COMPLETED", event_types)

    # ── Test 7: No geo hops → GEOINT_UNAVAILABLE ─────────────────────
    def test_no_geo_hops_produces_unavailable_event(self) -> None:
        """When GeoIP returns empty list, GEOINT_UNAVAILABLE should be recorded."""
        from unittest.mock import AsyncMock, patch

        case_id = self.client.post(
            "/api/v1/cases", json={"title": "GeoIP Unavailable Test"}
        ).json()["id"]

        with patch(
            "app.services.geo_osint.GeoTrackerService.track_hops",
            new_callable=AsyncMock,
            return_value=[],  # Empty hops simulates GeoIP unavailable
        ):
            self.client.post(
                "/api/v1/investigate",
                data={"case_id": case_id},
                files={"file": ("test.eml", SAMPLE_EML_BENIGN.encode(), "message/rfc822")},
            )

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("GEOINT_UNAVAILABLE", event_types)
        self.assertNotIn("GEOINT_COMPLETED", event_types)

    # ── Test 8: Timeline persists to file database ────────────────────
    def test_timeline_persists_to_database(self) -> None:
        """Timeline data stored in DB file survives across sessions."""
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "Persistence Test"}
        ).json()["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_PHISHING.encode(), "message/rfc822")},
        )

        # Simulate restart: create a new client against the same engine
        client2 = TestClient(app)
        tl = client2.get(f"/api/v1/cases/{case_id}/timeline").json()
        event_types = [e["event_type"] for e in tl["events"]]
        self.assertIn("CASE_CREATED", event_types)
        self.assertIn("EMAIL_PARSED", event_types)
        self.assertGreater(tl["total_events"], 2)

    # ── Test 9: Timestamps are valid ISO 8601 ─────────────────────────
    def test_timeline_timestamps_are_iso8601(self) -> None:
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "ISO 8601 Test"}
        ).json()["id"]

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        for evt in tl["events"]:
            ts = evt.get("timestamp", "")
            self.assertTrue(len(ts) > 10, f"Timestamp too short: {ts!r}")
            # Should parse as ISO datetime
            try:
                datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                self.fail(f"Timestamp is not valid ISO 8601: {ts!r}")

    # ── Test 10: Timeline endpoint returns summary fields ─────────────
    def test_timeline_endpoint_summary_fields(self) -> None:
        case_id = self.client.post(
            "/api/v1/cases", json={"title": "Summary Fields Test"}
        ).json()["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_BENIGN.encode(), "message/rfc822")},
        )

        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        self.assertIn("case_id", tl)
        self.assertIn("case_number", tl)
        self.assertIn("total_events", tl)
        self.assertIn("first_event_at", tl)
        self.assertIn("last_event_at", tl)
        self.assertIn("events", tl)
        self.assertEqual(tl["case_id"], case_id)
        self.assertTrue(tl["case_number"].startswith("MT-2026-"))
        self.assertGreater(tl["total_events"], 0)

    # ── Test 11: 404 for nonexistent case timeline ────────────────────
    def test_timeline_returns_404_for_missing_case(self) -> None:
        resp = self.client.get("/api/v1/cases/999999/timeline")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
