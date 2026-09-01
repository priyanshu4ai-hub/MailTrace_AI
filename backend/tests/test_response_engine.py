from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import ResponseAction
from app.db.session import get_db
from app.main import app
from app.services import response_service


class TestResponseEngine(unittest.TestCase):
    """Comprehensive test suite for Case 10: Incident Response & SOC Automation."""

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

    def _setup_phishing_case(self) -> int:
        """Helper: Create a case, upload a phishing EML, and trigger investigation."""
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "SBI Phishing Credential Harvesting", "severity": "high"},
        )
        case_id = c_resp.json()["id"]

        sample_eml = (
            "From: alerts@sbi-secure-update.co.in\n"
            "To: victim@target.in\n"
            "Subject: Immediate Action Required: SBI YONO Account Suspended\n"
            "Date: Tue, 01 Sep 2026 11:30:00 +0530\n"
            "Message-ID: <sbi-phish-900@sbi-secure-update.co.in>\n"
            "Authentication-Results: mx.target.in; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Dear Customer, your SBI account is suspended. "
            "Update KYC immediately at http://sbi-secure-update.co.in/kyc"
        )

        inv_resp = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("sbi_phish.eml", sample_eml.encode("utf-8"), "message/rfc822")},
        )
        self.assertEqual(inv_resp.status_code, 200)
        return case_id

    # ── 1. Recommendation Generation ──

    def test_recommendation_generation(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total_actions"], 1)
        self.assertGreaterEqual(data["recommended_count"], 1)
        # All new actions should start in RECOMMENDED status
        for action in data["actions"]:
            if action["status"] == "RECOMMENDED":
                self.assertIn("response_id", action)
                self.assertTrue(action["response_id"].startswith("RSP-"))

    def test_malicious_url_generates_block_url(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        data = resp.json()
        action_types = [a["action_type"] for a in data["actions"]]
        # URL or Domain block should be generated for malicious indicators
        self.assertTrue(
            any(t in ("BLOCK_URL", "BLOCK_DOMAIN") for t in action_types),
            f"Expected BLOCK_URL or BLOCK_DOMAIN in {action_types}",
        )

    def test_phishing_case_generates_mailbox_search(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        data = resp.json()
        action_types = [a["action_type"] for a in data["actions"]]
        self.assertIn("SEARCH_MAILBOX", action_types)

    def test_phishing_case_generates_credential_reset(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        data = resp.json()
        action_types = [a["action_type"] for a in data["actions"]]
        self.assertIn("RESET_CREDENTIAL_RECOMMENDATION", action_types)

    def test_auth_failure_generates_isolate_artifact(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        data = resp.json()
        action_types = [a["action_type"] for a in data["actions"]]
        self.assertIn("ISOLATE_ARTIFACT", action_types)

    def test_benign_ioc_does_not_generate_block(self) -> None:
        """Create a case with a safe email and verify no block recommendations are generated."""
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Safe Email Verification", "severity": "low"},
        )
        case_id = c_resp.json()["id"]

        safe_eml = (
            "From: john@google.com\n"
            "To: jane@company.com\n"
            "Subject: Meeting Tomorrow\n"
            "Date: Tue, 01 Sep 2026 10:00:00 +0530\n"
            "Message-ID: <safe-meeting-01@google.com>\n"
            "Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass\n\n"
            "Hi Jane, let's meet tomorrow at 10am."
        )

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("safe.eml", safe_eml.encode("utf-8"), "message/rfc822")},
        )

        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        data = resp.json()
        block_actions = [a for a in data["actions"] if a["action_type"] in ("BLOCK_DOMAIN", "BLOCK_IP", "BLOCK_URL")]
        self.assertEqual(len(block_actions), 0, "Benign email should not generate BLOCK actions")

    # ── 2. Approval & Rejection Workflow ──

    def test_approval_transition(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions_resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        recommended = [a for a in actions_resp.json()["actions"] if a["status"] == "RECOMMENDED"]
        self.assertGreater(len(recommended), 0)

        action = recommended[0]
        approve_resp = self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/approve")
        self.assertEqual(approve_resp.status_code, 200)
        self.assertEqual(approve_resp.json()["status"], "APPROVED")
        self.assertIsNotNone(approve_resp.json()["approved_at"])

    def test_rejection_transition(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions_resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        recommended = [a for a in actions_resp.json()["actions"] if a["status"] == "RECOMMENDED"]
        self.assertGreater(len(recommended), 0)

        action = recommended[0]
        reject_resp = self.client.post(
            f"/api/v1/cases/{case_id}/responses/{action['response_id']}/reject",
            json={"reason": "Not required at this time."},
        )
        self.assertEqual(reject_resp.status_code, 200)
        self.assertEqual(reject_resp.json()["status"], "REJECTED")

    # ── 3. Execution Guardrails ──

    def test_execution_requires_approval(self) -> None:
        """Attempting to execute a RECOMMENDED action must fail."""
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions_resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        recommended = [a for a in actions_resp.json()["actions"] if a["status"] == "RECOMMENDED"]
        action = recommended[0]

        exec_resp = self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/execute")
        self.assertEqual(exec_resp.status_code, 400)
        self.assertIn("approval required", exec_resp.json()["detail"].lower())

    def test_rejected_action_cannot_execute(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions_resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        action = [a for a in actions_resp.json()["actions"] if a["status"] == "RECOMMENDED"][0]

        self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/reject")
        exec_resp = self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/execute")
        self.assertEqual(exec_resp.status_code, 400)

    def test_approved_action_executes_simulation(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions_resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        action = [a for a in actions_resp.json()["actions"] if a["status"] == "RECOMMENDED"][0]

        self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/approve")
        exec_resp = self.client.post(f"/api/v1/cases/{case_id}/responses/{action['response_id']}/execute")
        self.assertEqual(exec_resp.status_code, 200)

        data = exec_resp.json()
        self.assertEqual(data["status"], "EXECUTED")
        self.assertEqual(data["execution_mode"], "SIMULATION")
        self.assertEqual(data["result"], "SIMULATED_SUCCESS")
        self.assertIn("SIMULATION", data["result_message"])

    # ── 4. Timeline & Ledger Integration ──

    def test_timeline_events_generated(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        t_resp = self.client.get(f"/api/v1/cases/{case_id}/timeline")
        events = t_resp.json()["events"]
        event_types = [e["event_type"] for e in events]
        self.assertIn("RESPONSE_RECOMMENDED", event_types)

    def test_approval_timeline_and_ledger(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["actions"]
        rec = [a for a in actions if a["status"] == "RECOMMENDED"][0]
        self.client.post(f"/api/v1/cases/{case_id}/responses/{rec['response_id']}/approve")

        t_resp = self.client.get(f"/api/v1/cases/{case_id}/timeline")
        types = [e["event_type"] for e in t_resp.json()["events"]]
        self.assertIn("RESPONSE_APPROVED", types)

        # Ledger should still be intact
        l_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(l_resp.status_code, 200)
        self.assertTrue(l_resp.json()["is_valid"])

    def test_execution_ledger_sealing(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["actions"]
        rec = [a for a in actions if a["status"] == "RECOMMENDED"][0]

        self.client.post(f"/api/v1/cases/{case_id}/responses/{rec['response_id']}/approve")
        self.client.post(f"/api/v1/cases/{case_id}/responses/{rec['response_id']}/execute")

        t_resp = self.client.get(f"/api/v1/cases/{case_id}/timeline")
        types = [e["event_type"] for e in t_resp.json()["events"]]
        self.assertIn("RESPONSE_EXECUTED", types)

        # Verify ledger integrity
        l_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(l_resp.status_code, 200)
        self.assertTrue(l_resp.json()["is_valid"])
        self.assertEqual(l_resp.json()["status"], "intact")

        # Ledger entries should include RESPONSE_ACTION
        lg = self.client.get(f"/api/v1/cases/{case_id}/ledger")
        entry_types = [e["entry_type"] for e in lg.json()["entries"]]
        self.assertIn("RESPONSE_ACTION", entry_types)

    # ── 5. Response History & Immutability ──

    def test_response_history_and_separateness(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        resp = self.client.get(f"/api/v1/cases/{case_id}/responses")
        actions = resp.json()["actions"]
        self.assertGreaterEqual(len(actions), 2)
        ids = [a["response_id"] for a in actions]
        self.assertEqual(len(ids), len(set(ids)), "All response IDs must be unique")

    def test_single_response_retrieval(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["actions"]
        action = actions[0]

        detail_resp = self.client.get(f"/api/v1/cases/{case_id}/responses/{action['response_id']}")
        self.assertEqual(detail_resp.status_code, 200)
        self.assertEqual(detail_resp.json()["response_id"], action["response_id"])

    # ── 6. Error Handling ──

    def test_nonexistent_case_404(self) -> None:
        resp = self.client.post("/api/v1/cases/99999/responses/recommend")
        self.assertEqual(resp.status_code, 404)

    def test_nonexistent_response_404(self) -> None:
        case_id = self._setup_phishing_case()
        resp = self.client.get(f"/api/v1/cases/{case_id}/responses/RSP-FAKE-9999")
        self.assertEqual(resp.status_code, 404)

    def test_invalid_state_transition_rejected(self) -> None:
        """Approving an already-executed action should fail."""
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["actions"]
        rec = [a for a in actions if a["status"] == "RECOMMENDED"][0]
        rid = rec["response_id"]

        self.client.post(f"/api/v1/cases/{case_id}/responses/{rid}/approve")
        self.client.post(f"/api/v1/cases/{case_id}/responses/{rid}/execute")

        # Trying to approve again should fail
        resp = self.client.post(f"/api/v1/cases/{case_id}/responses/{rid}/approve")
        self.assertEqual(resp.status_code, 400)

    # ── 7. Report Integration ──

    def test_report_includes_response_activity(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")

        actions = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["actions"]
        rec = [a for a in actions if a["status"] == "RECOMMENDED"][0]
        self.client.post(f"/api/v1/cases/{case_id}/responses/{rec['response_id']}/approve")
        self.client.post(f"/api/v1/cases/{case_id}/responses/{rec['response_id']}/execute")

        # Generate new DFIR report
        rpt = self.client.post(f"/api/v1/cases/{case_id}/reports", json={"report_type": "DFIR_FULL"})
        self.assertEqual(rpt.status_code, 201)
        content = rpt.json()["content"]
        self.assertIn("response_actions_summary", content)
        self.assertGreaterEqual(content["response_actions_summary"]["total_response_actions"], 1)
        self.assertGreaterEqual(content["response_actions_summary"]["executed_count"], 1)

    # ── 8. Deduplication ──

    def test_duplicate_recommendations_prevented(self) -> None:
        case_id = self._setup_phishing_case()
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        count1 = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["total_actions"]

        # Run again — should not create duplicates
        self.client.post(f"/api/v1/cases/{case_id}/responses/recommend")
        count2 = self.client.get(f"/api/v1/cases/{case_id}/responses").json()["total_actions"]

        self.assertEqual(count1, count2, "Re-running recommendations should not create duplicate actions")


if __name__ == "__main__":
    unittest.main()
