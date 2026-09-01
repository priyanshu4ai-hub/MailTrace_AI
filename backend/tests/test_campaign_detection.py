"""
Case 6 — Campaign Detection & Multi-Email Correlation Tests.

Tests:
1. One email -> insufficient_data status.
2. Two emails with same URL -> campaign detected.
3. Two emails with same domain -> campaign detected when threshold met.
4. Two emails with same IP -> correlation detected.
5. Same sender domain -> correlation signal.
6. Different unrelated emails -> no campaign.
7. Similar subjects -> correlation signal.
8. Multiple shared IOCs and deduplication.
9. Campaign score capped at 100.
10. Campaign confidence in range 0-100.
11. Campaign members structure and properties.
12. Campaign retrieval API (list and detail).
13. Case campaign detection API.
14. Campaign timeline event recorded.
15. Campaign attack graph generation.
16. AI summary generated deterministically without LLM.
17. Defensive recommendations based on evidence.
"""

from __future__ import annotations

import json
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.campaign_detector import CampaignDetectionService

SAMPLE_EML_A = """From: "Security Alert" <alert@targetcorp-security.com>
To: user1@targetcorp.com
Subject: URGENT: MFA Authentication Reset
Date: Tue, 01 Sep 2026 10:00:00 +0000
Message-ID: <camp-001@targetcorp-security.com>
Received: from mx.targetcorp.com (mx.targetcorp.com [198.51.100.22]) by mailstore.targetcorp.com

Please verify your credentials at https://login-targetcorp-auth.com/verify
"""

SAMPLE_EML_B = """From: "IT Support Desk" <support@targetcorp-security.com>
To: user2@targetcorp.com
Subject: URGENT: MFA Authentication Confirmation
Date: Tue, 01 Sep 2026 10:15:00 +0000
Message-ID: <camp-002@targetcorp-security.com>
Received: from mx.targetcorp.com (mx.targetcorp.com [198.51.100.22]) by mailstore.targetcorp.com

Please verify your credentials at https://login-targetcorp-auth.com/verify
"""

SAMPLE_EML_UNRELATED = """From: "Newsletter" <news@technews-weekly.org>
To: user1@targetcorp.com
Subject: Weekly Tech Digest #42
Date: Tue, 01 Sep 2026 11:00:00 +0000
Message-ID: <news-001@technews-weekly.org>
Received: from mail.technews-weekly.org (mail.technews-weekly.org [203.0.113.88]) by mx.targetcorp.com

Check out our latest articles at https://technews-weekly.org/digest
"""


class CampaignDetectionTests(unittest.TestCase):
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
        self.service = CampaignDetectionService()

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)

    # 1. One email -> insufficient_data
    def test_one_email_insufficient_data(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Single Message",
                "sender": "alert@phish.com",
                "urls": ["http://phish.com/login"],
                "received_headers": ["from [198.51.100.22]"],
            }
        ]
        result = self.service.detect_campaigns(items)
        self.assertEqual(result["status"], "insufficient_data")
        self.assertEqual(result["campaigns_detected"], 0)
        self.assertEqual(len(result["campaigns"]), 0)

    # 2. Two emails with same URL -> campaign detected
    def test_two_emails_same_url_detected(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Password Expiry Notice",
                "sender": "sec@auth-service.com",
                "urls": ["https://auth-service.com/login"],
                "threat_type": "Credential Phishing",
            },
            {
                "id": 2,
                "subject": "Account Verification Required",
                "sender": "help@other-service.com",
                "urls": ["https://auth-service.com/login"],
                "threat_type": "Credential Phishing",
            },
        ]
        result = self.service.detect_campaigns(items)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["campaigns_detected"], 1)
        campaign = result["campaigns"][0]
        self.assertGreaterEqual(campaign["confidence"], 50)
        self.assertEqual(campaign["email_count"], 2)

        # Verify shared URL is recorded
        shared_urls = [i for i in campaign["shared_indicators"] if i["type"] == "url"]
        self.assertEqual(len(shared_urls), 1)
        self.assertEqual(shared_urls[0]["indicator"], "https://auth-service.com/login")

    # 3. Two emails with same domain -> campaign detected
    def test_two_emails_same_domain_detected(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Invoice Attachment",
                "sender": "billing@targetcorp-fraud.com",
                "urls": ["http://targetcorp-fraud.com/inv1"],
                "threat_type": "Credential Phishing",
            },
            {
                "id": 2,
                "subject": "Past Due Notice",
                "sender": "accounts@targetcorp-fraud.com",
                "urls": ["http://targetcorp-fraud.com/inv2"],
                "threat_type": "Credential Phishing",
            },
        ]
        result = self.service.detect_campaigns(items)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["campaigns_detected"], 1)
        self.assertEqual(result["campaigns"][0]["threat_type"], "Credential Phishing")

    # 4. Two emails with same IP -> correlation detected
    def test_two_emails_same_ip_detected(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Payment Confirmation",
                "sender": "sender1@domain1.com",
                "received_headers": ["from relay.host (185.220.101.55) by mx"],
                "urls": ["http://url1.com"],
            },
            {
                "id": 2,
                "subject": "Payment Receipt",
                "sender": "sender2@domain2.com",
                "received_headers": ["from relay.host (185.220.101.55) by mx"],
                "urls": ["http://url2.com"],
            },
        ]
        f_a = self.service._extract_features(items[0])
        f_b = self.service._extract_features(items[1])
        pair = self.service._score_pair(f_a, f_b)
        signals = [s["signal"] for s in pair["signals"]]
        self.assertIn("SHARED_IP", signals)
        self.assertGreaterEqual(pair["score"], 25)

    # 5. Same sender domain correlation
    def test_same_sender_domain_signal(self) -> None:
        items = [
            {"id": 1, "subject": "Alert 1", "sender": "user1@attacker-spoof.net"},
            {"id": 2, "subject": "Alert 2", "sender": "user2@attacker-spoof.net"},
        ]
        f_a = self.service._extract_features(items[0])
        f_b = self.service._extract_features(items[1])
        pair = self.service._score_pair(f_a, f_b)
        signals = [s["signal"] for s in pair["signals"]]
        self.assertIn("SAME_SENDER_DOMAIN", signals)

    # 6. Different unrelated emails -> no campaign
    def test_different_unrelated_emails_no_campaign(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Marketing Newsletter",
                "sender": "news@company-a.com",
                "urls": ["https://company-a.com/blog"],
                "received_headers": ["from [10.0.0.1]"],
            },
            {
                "id": 2,
                "subject": "Flight Itinerary",
                "sender": "reservations@airline-b.org",
                "urls": ["https://airline-b.org/ticket"],
                "received_headers": ["from [192.168.1.1]"],
            },
        ]
        result = self.service.detect_campaigns(items)
        self.assertEqual(result["status"], "no_campaigns_detected")
        self.assertEqual(result["campaigns_detected"], 0)

    # 7. Similar subjects produce correlation signal
    def test_subject_similarity_signal(self) -> None:
        items = [
            {"id": 1, "subject": "URGENT: MFA Authentication Reset Required", "sender": "a@phish.com", "urls": ["http://phish.com"]},
            {"id": 2, "subject": "URGENT: MFA Authentication Reset Confirmation", "sender": "b@phish.com", "urls": ["http://phish.com"]},
        ]
        f_a = self.service._extract_features(items[0])
        f_b = self.service._extract_features(items[1])
        pair = self.service._score_pair(f_a, f_b)
        signals = [s["signal"] for s in pair["signals"]]
        self.assertIn("SUBJECT_SIMILARITY", signals)

    # 8. Multiple shared IOCs and deduplication
    def test_multiple_shared_iocs_and_deduplication(self) -> None:
        items = [
            {
                "id": 1,
                "subject": "Action Required",
                "sender": "admin@targetcorp-auth.com",
                "urls": ["https://login-targetcorp-auth.com/verify"],
                "received_headers": ["from [185.220.101.45]"],
            },
            {
                "id": 2,
                "subject": "Action Required",
                "sender": "service@targetcorp-auth.com",
                "urls": ["https://login-targetcorp-auth.com/verify"],
                "received_headers": ["from [185.220.101.45]"],
            },
        ]
        result = self.service.detect_campaigns(items)
        campaign = result["campaigns"][0]
        self.assertGreaterEqual(campaign["shared_ioc_count"], 2)
        # Verify no duplicate indicator keys
        seen_keys = [f"{i['type']}:{i['indicator']}" for i in campaign["shared_indicators"]]
        self.assertEqual(len(seen_keys), len(set(seen_keys)))

    # 9. Campaign score capped at 100
    def test_campaign_score_capped_at_100(self) -> None:
        # Items matching on ALL dimensions (URL + Domain + IP + Sender Domain + Reply-To + Subject + Threat Type)
        items = [
            {
                "id": 1,
                "subject": "Critical Security Update",
                "sender": "sec@evil.com",
                "reply_to": "drop@evil.com",
                "urls": ["http://evil.com/payload"],
                "received_headers": ["from [198.51.100.99]"],
                "threat_type": "Credential Phishing",
            },
            {
                "id": 2,
                "subject": "Critical Security Update",
                "sender": "sec@evil.com",
                "reply_to": "drop@evil.com",
                "urls": ["http://evil.com/payload"],
                "received_headers": ["from [198.51.100.99]"],
                "threat_type": "Credential Phishing",
            },
        ]
        f_a = self.service._extract_features(items[0])
        f_b = self.service._extract_features(items[1])
        pair = self.service._score_pair(f_a, f_b)
        self.assertEqual(pair["score"], 100)

    # 10. Campaign confidence is valid between 0 and 100
    def test_campaign_confidence_range(self) -> None:
        items = [
            {"id": 1, "subject": "Alert 1", "urls": ["http://shared.com/1"], "sender": "a@shared.com"},
            {"id": 2, "subject": "Alert 2", "urls": ["http://shared.com/1"], "sender": "b@shared.com"},
        ]
        result = self.service.detect_campaigns(items)
        campaign = result["campaigns"][0]
        self.assertGreaterEqual(campaign["confidence"], 0)
        self.assertLessEqual(campaign["confidence"], 100)

    # 11. Campaign members structure
    def test_campaign_members_structure(self) -> None:
        items = [
            {"id": 101, "subject": "Subj 1", "sender": "a@phish.com", "recipient": "user1@corp.com", "urls": ["http://phish.com/a"]},
            {"id": 102, "subject": "Subj 2", "sender": "b@phish.com", "recipient": "user2@corp.com", "urls": ["http://phish.com/a"]},
        ]
        result = self.service.detect_campaigns(items)
        campaign = result["campaigns"][0]
        self.assertEqual(len(campaign["emails"]), 2)
        self.assertEqual(campaign["emails"][0]["artifact_id"], 101)
        self.assertEqual(campaign["emails"][1]["artifact_id"], 102)

    # 12. Campaign attack graph contains converging multi-email structure
    def test_campaign_attack_graph_generation(self) -> None:
        items = [
            {"id": 1, "subject": "Phish 1", "sender": "a@bad.com", "urls": ["http://bad.com/login"]},
            {"id": 2, "subject": "Phish 2", "sender": "b@bad.com", "urls": ["http://bad.com/login"]},
        ]
        result = self.service.detect_campaigns(items)
        graph = result["campaigns"][0]["attack_graph"]
        self.assertIn("nodes", graph)
        self.assertIn("links", graph)
        self.assertGreaterEqual(len(graph["nodes"]), 3)
        self.assertGreaterEqual(len(graph["links"]), 2)

    # 13. AI / Deterministic narrative generated without hallucinations
    def test_ai_summary_generated_deterministically(self) -> None:
        items = [
            {"id": 1, "subject": "MFA 1", "sender": "sec@spoof.org", "urls": ["http://spoof.org/login"]},
            {"id": 2, "subject": "MFA 2", "sender": "it@spoof.org", "urls": ["http://spoof.org/login"]},
        ]
        result = self.service.detect_campaigns(items)
        summary = result["campaigns"][0]["ai_summary"]
        self.assertIn("MailTrace AI", summary)
        self.assertIn("coordinated", summary)
        self.assertIn("without attributing specific threat-actor identity", summary)

    # 14. Defensive recommendations cite evidence
    def test_campaign_recommendations_evidence_based(self) -> None:
        items = [
            {"id": 1, "subject": "Lure 1", "sender": "a@phish-corp.net", "urls": ["http://phish-corp.net/auth"], "received_headers": ["from [198.51.100.22]"]},
            {"id": 2, "subject": "Lure 2", "sender": "b@phish-corp.net", "urls": ["http://phish-corp.net/auth"], "received_headers": ["from [198.51.100.22]"]},
        ]
        result = self.service.detect_campaigns(items)
        recs = result["campaigns"][0]["recommendations"]
        self.assertTrue(any("phish-corp.net" in r for r in recs) or any("DNS block" in r for r in recs))
        self.assertTrue(any("198.51.100.22" in r for r in recs) or any("firewall" in r.lower() for r in recs))

    # 15. API: Case campaign detection and timeline event
    def test_api_case_campaign_detection_and_timeline(self) -> None:
        # Create case
        case_resp = self.client.post("/api/v1/cases", json={"title": "Campaign Test Case"}).json()
        case_id = case_resp["id"]

        # Upload two correlated emails
        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("email1.eml", SAMPLE_EML_A.encode(), "message/rfc822")},
        )
        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("email2.eml", SAMPLE_EML_B.encode(), "message/rfc822")},
        )

        # Trigger campaign detection for case
        detect_resp = self.client.post(f"/api/v1/cases/{case_id}/campaigns/detect")
        self.assertEqual(detect_resp.status_code, 200)
        data = detect_resp.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["campaigns_detected"], 1)

        # Verify timeline recorded CAMPAIGN_DETECTION_COMPLETED event
        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        camp_events = [e for e in tl["events"] if e["event_type"] == "CAMPAIGN_DETECTION_COMPLETED"]
        self.assertEqual(len(camp_events), 1)

    # 16. API: Campaign list & detail retrieval
    def test_api_campaign_list_and_detail(self) -> None:
        case_resp = self.client.post("/api/v1/cases", json={"title": "Campaign API Case"}).json()
        case_id = case_resp["id"]

        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("email1.eml", SAMPLE_EML_A.encode(), "message/rfc822")},
        )
        self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("email2.eml", SAMPLE_EML_B.encode(), "message/rfc822")},
        )

        self.client.post(f"/api/v1/cases/{case_id}/campaigns/detect")

        # List all campaigns
        list_resp = self.client.get("/api/v1/campaigns")
        self.assertEqual(list_resp.status_code, 200)
        list_data = list_resp.json()
        self.assertGreaterEqual(list_data["total_campaigns"], 1)
        camp_id_str = list_data["campaigns"][0]["campaign_id"]

        # Detail retrieval
        detail_resp = self.client.get(f"/api/v1/campaigns/{camp_id_str}")
        self.assertEqual(detail_resp.status_code, 200)
        detail_data = detail_resp.json()
        self.assertEqual(detail_data["campaign_id"], camp_id_str)
        self.assertEqual(detail_data["email_count"], 2)


if __name__ == "__main__":
    unittest.main()
