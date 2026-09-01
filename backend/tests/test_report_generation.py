from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Case, EvidenceLedger, Report, TimelineEvent
from app.db.session import get_db
from app.main import app
from app.services import case_service, evidence_ledger, report_service


class TestReportGeneration(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        Base.metadata.create_all(bind=self.engine)

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)

    def _setup_case_with_investigation(self) -> int:
        """Helper to create a case with an investigated phishing artifact and notes."""
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "SBI Credential Harvesting Case", "severity": "high"},
        )
        case_id = c_resp.json()["id"]

        sample_eml = (
            "From: alerts@sbi-secure-update.co.in\n"
            "To: victim@target.in\n"
            "Subject: Immediate Action Required: SBI YONO Account Suspended\n"
            "Date: Tue, 01 Sep 2026 11:30:00 +0530\n"
            "Message-ID: <sbi-phish-900@sbi-secure-update.co.in>\n"
            "Authentication-Results: mx.target.in; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Dear Customer, your SBI account is suspended. Update KYC immediately at http://sbi-secure-update.co.in/kyc"
        )

        inv_resp = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("sbi_phish.eml", sample_eml.encode("utf-8"), "message/rfc822")},
        )
        self.assertEqual(inv_resp.status_code, 200)

        # Add analyst note
        self.client.post(
            f"/api/v1/cases/{case_id}/notes",
            json={"note": "Confirmed malicious domain mimicking SBI YONO banking."},
        )

        return case_id

    def test_dfir_full_report_generation(self) -> None:
        case_id = self._setup_case_with_investigation()

        resp = self.client.post(
            f"/api/v1/cases/{case_id}/reports",
            json={"report_type": "DFIR_FULL", "title": "Comprehensive DFIR Incident Report"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        self.assertIn("report_id", data)
        self.assertTrue(data["report_id"].startswith("RPT-"))
        self.assertEqual(data["report_type"], "DFIR_FULL")
        self.assertEqual(len(data["report_hash"]), 64)
        self.assertEqual(data["ledger_status"], "VERIFIED")

        content = data["content"]
        # Verify 11 Core DFIR Sections
        self.assertIn("executive_summary", content)
        self.assertIn("incident_details", content)
        self.assertIn("email_forensics", content)
        self.assertIn("authentication_analysis", content)
        self.assertIn("threat_intelligence", content)
        self.assertIn("attack_graph_summary", content)
        self.assertIn("campaign_analysis", content)
        self.assertIn("forensic_timeline", content)
        self.assertIn("evidence_integrity", content)
        self.assertIn("analyst_notes", content)
        self.assertIn("response_recommendations", content)

        # Verify real values populated
        self.assertEqual(content["executive_summary"]["case_title"], "SBI Credential Harvesting Case")
        self.assertEqual(content["email_forensics"]["artifact_count"], 1)
        self.assertEqual(content["authentication_analysis"]["spf"], "FAIL")
        self.assertGreater(content["forensic_timeline"]["total_events"], 3)
        self.assertEqual(content["evidence_integrity"]["ledger_status"], "VERIFIED")
        self.assertGreaterEqual(len(content["response_recommendations"]["recommendations"]), 1)

    def test_executive_summary_generation(self) -> None:
        case_id = self._setup_case_with_investigation()

        resp = self.client.post(
            f"/api/v1/cases/{case_id}/reports",
            json={"report_type": "EXECUTIVE_SUMMARY"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()

        self.assertEqual(data["report_type"], "EXECUTIVE_SUMMARY")
        content = data["content"]
        self.assertIn("executive_summary", content)
        self.assertIn("incident_details", content)
        self.assertIn("threat_intelligence_summary", content)
        self.assertIn("response_recommendations", content)

    def test_report_hash_determinism_and_sensitivity(self) -> None:
        data1 = {"case": "MT-2026-0001", "verdict": "PHISHING", "score": 95}
        data2 = {"verdict": "PHISHING", "score": 95, "case": "MT-2026-0001"}
        data3 = {"case": "MT-2026-0001", "verdict": "PHISHING", "score": 96}

        h1 = report_service.canonical_report_hash(data1)
        h2 = report_service.canonical_report_hash(data2)
        h3 = report_service.canonical_report_hash(data3)

        self.assertEqual(len(h1), 64)
        self.assertEqual(h1, h2)  # Deterministic sorting
        self.assertNotEqual(h1, h3)  # Sensitive to content changes

    def test_report_generated_timeline_event(self) -> None:
        case_id = self._setup_case_with_investigation()

        resp = self.client.post(f"/api/v1/cases/{case_id}/reports")
        rep_id = resp.json()["report_id"]

        # Check timeline events for case
        t_resp = self.client.get(f"/api/v1/cases/{case_id}/timeline")
        self.assertEqual(t_resp.status_code, 200)
        events = t_resp.json()["events"]
        event_types = [e["event_type"] for e in events]
        self.assertIn("REPORT_GENERATED", event_types)

        # Check metadata
        report_evt = next(e for e in events if e["event_type"] == "REPORT_GENERATED")
        self.assertIn(rep_id, report_evt["description"])

    def test_report_ledger_sealing(self) -> None:
        case_id = self._setup_case_with_investigation()

        resp = self.client.post(f"/api/v1/cases/{case_id}/reports")
        rep_data = resp.json()

        # Check ledger entries for case
        l_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger")
        self.assertEqual(l_resp.status_code, 200)
        l_data = l_resp.json()
        self.assertTrue(l_data["is_valid"])

        types = [e["entry_type"] for e in l_data["entries"]]
        self.assertIn("REPORT_GENERATED", types)

        report_block = next(e for e in l_data["entries"] if e["entry_type"] == "REPORT_GENERATED")
        self.assertEqual(report_block["data_hash"], rep_data["report_hash"])
        self.assertEqual(report_block["reference_id"], rep_data["report_id"])

        # Check live verify endpoint remains intact
        v_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(v_resp.status_code, 200)
        self.assertTrue(v_resp.json()["is_valid"])
        self.assertEqual(v_resp.json()["status"], "intact")

    def test_report_history_and_immutability(self) -> None:
        case_id = self._setup_case_with_investigation()

        # 1. Generate first report (DFIR_FULL)
        r1_resp = self.client.post(f"/api/v1/cases/{case_id}/reports", json={"report_type": "DFIR_FULL"})
        r1_id = r1_resp.json()["report_id"]

        # 2. Generate second report (EXECUTIVE_SUMMARY)
        r2_resp = self.client.post(f"/api/v1/cases/{case_id}/reports", json={"report_type": "EXECUTIVE_SUMMARY"})
        r2_id = r2_resp.json()["report_id"]

        self.assertNotEqual(r1_id, r2_id)

        # 3. Retrieve report history
        hist_resp = self.client.get(f"/api/v1/cases/{case_id}/reports")
        self.assertEqual(hist_resp.status_code, 200)
        hist = hist_resp.json()
        self.assertEqual(hist["total_reports"], 2)
        r_ids = [r["report_id"] for r in hist["reports"]]
        self.assertIn(r1_id, r_ids)
        self.assertIn(r2_id, r_ids)

        # 4. First report content remains unchanged
        get_r1 = self.client.get(f"/api/v1/cases/{case_id}/reports/{r1_id}")
        self.assertEqual(get_r1.status_code, 200)
        self.assertEqual(get_r1.json()["report_type"], "DFIR_FULL")

    def test_markdown_export_endpoint(self) -> None:
        case_id = self._setup_case_with_investigation()

        r_resp = self.client.post(f"/api/v1/cases/{case_id}/reports")
        r_id = r_resp.json()["report_id"]

        md_resp = self.client.get(f"/api/v1/cases/{case_id}/reports/{r_id}/markdown")
        self.assertEqual(md_resp.status_code, 200)
        self.assertIn("text/markdown", md_resp.headers.get("content-type", ""))
        self.assertIn("MAILTRACE AI — DIGITAL FORENSICS & INCIDENT RESPONSE", md_resp.text)
        self.assertIn(r_id, md_resp.text)

    def test_nonexistent_case_and_report_404(self) -> None:
        resp = self.client.post("/api/v1/cases/99999/reports")
        self.assertEqual(resp.status_code, 404)

        resp2 = self.client.get("/api/v1/cases/99999/reports")
        self.assertEqual(resp2.status_code, 404)

        resp3 = self.client.get("/api/v1/cases/1/reports/RPT-NONEXISTENT")
        self.assertEqual(resp3.status_code, 404)


if __name__ == "__main__":
    unittest.main()
