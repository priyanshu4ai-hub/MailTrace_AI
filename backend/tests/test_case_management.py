from __future__ import annotations

import os
import tempfile
import unittest

from fastapi.testclient import TestClient

# Create a temporary file database for testing
tmp_db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
tmp_db_file.close()

os.environ["DATABASE_URL"] = f"sqlite:///{tmp_db_file.name}"

from app.db.base import Base
from app.db.session import engine
from app.main import app


class CaseManagementTests(unittest.TestCase):
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

    def test_create_and_list_cases(self) -> None:
        # 1. Create Case
        response = self.client.post(
            "/api/v1/cases",
            json={
                "title": "M365 Credential Harvesting Attack",
                "description": "Targeted BEC spearphishing campaign.",
                "severity": "high",
                "threat_type": "phishing",
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["title"], "M365 Credential Harvesting Attack")
        self.assertTrue(data["case_number"].startswith("MT-2026-"))
        self.assertEqual(data["severity"], "high")
        self.assertEqual(data["status"], "open")

        case_id = data["id"]

        # 2. List Cases
        list_resp = self.client.get("/api/v1/cases")
        self.assertEqual(list_resp.status_code, 200)
        cases_list = list_resp.json()
        self.assertEqual(len(cases_list), 1)
        self.assertEqual(cases_list[0]["id"], case_id)

    def test_retrieve_and_update_case(self) -> None:
        # Create Case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Suspicious Executive Email", "severity": "medium"},
        )
        case_id = c_resp.json()["id"]

        # Retrieve Case
        get_resp = self.client.get(f"/api/v1/cases/{case_id}")
        self.assertEqual(get_resp.status_code, 200)
        self.assertEqual(get_resp.json()["title"], "Suspicious Executive Email")

        # Update Case
        patch_resp = self.client.patch(
            f"/api/v1/cases/{case_id}",
            json={"status": "in_progress", "severity": "critical"},
        )
        self.assertEqual(patch_resp.status_code, 200)
        updated_data = patch_resp.json()
        self.assertEqual(updated_data["status"], "in_progress")
        self.assertEqual(updated_data["severity"], "critical")

        # Verify timeline events recorded
        events = updated_data["timeline_events"]
        event_types = [e["event_type"] for e in events]
        self.assertIn("CASE_CREATED", event_types)
        self.assertIn("CASE_UPDATED", event_types)

    def test_attach_investigation_and_sha256_creation(self) -> None:
        # Create Case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Phishing Sample Analysis", "severity": "low"},
        )
        case_id = c_resp.json()["id"]

        sample_eml = (
            "From: security-alert@login-targetcorp-auth.com\n"
            "To: employee@target.com\n"
            "Subject: Urgent MFA Verification Required\n"
            "Date: Mon, 31 Aug 2026 14:22:18 +0000\n"
            "Message-ID: <test-12345@domain.com>\n"
            "Authentication-Results: mx.target.com; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Please verify your credentials at http://login-targetcorp-auth.com/login"
        )

        # Investigate with case_id
        inv_resp = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("phishing.eml", sample_eml.encode("utf-8"), "message/rfc822")},
        )
        self.assertEqual(inv_resp.status_code, 200)
        inv_data = inv_resp.json()
        self.assertIn("evidence_hash", inv_data)
        self.assertEqual(len(inv_data["evidence_hash"]), 64)  # SHA-256 hex digest length

        # Retrieve Case and verify artifact & result attached
        case_resp = self.client.get(f"/api/v1/cases/{case_id}")
        case_data = case_resp.json()

        self.assertEqual(len(case_data["email_artifacts"]), 1)
        self.assertEqual(case_data["email_artifacts"][0]["filename"], "phishing.eml")
        self.assertEqual(case_data["email_artifacts"][0]["sha256"], inv_data["evidence_hash"])

        self.assertEqual(len(case_data["investigation_results"]), 1)
        self.assertGreaterEqual(case_data["investigation_results"][0]["risk_score"], 65)

        event_types = [e["event_type"] for e in case_data["timeline_events"]]
        self.assertIn("EMAIL_UPLOADED", event_types)
        self.assertIn("INVESTIGATION_COMPLETED", event_types)

    def test_investigate_without_case_id_backward_compatibility(self) -> None:
        sample_eml = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test Message\n"
            "Date: Mon, 31 Aug 2026 12:00:00 +0000\n"
            "Message-ID: <msg-999@example.com>\n\n"
            "Hello world"
        )

        inv_resp = self.client.post(
            "/api/v1/investigate",
            files={"file": ("sample.eml", sample_eml.encode("utf-8"), "message/rfc822")},
        )
        self.assertEqual(inv_resp.status_code, 200)
        inv_data = inv_resp.json()
        self.assertEqual(inv_data["email"]["subject"], "Test Message")
        self.assertTrue("evidence_hash" in inv_data)

    def test_delete_case(self) -> None:
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Temporary Case to Delete"},
        )
        case_id = c_resp.json()["id"]

        del_resp = self.client.delete(f"/api/v1/cases/{case_id}")
        self.assertEqual(del_resp.status_code, 204)

        get_resp = self.client.get(f"/api/v1/cases/{case_id}")
        self.assertEqual(get_resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
