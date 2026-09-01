"""
Case 7 — Indian Phishing Demo Scenarios & Detection Tests.

Tests:
1. SBI brand impersonation detection.
2. HDFC, ICICI, Axis brand detection.
3. Paytm & PhonePe lookalike detection.
4. UPI path and keyword detection.
5. KYC detection signals.
6. PAN & Aadhaar detection signals.
7. EPFO / UAN detection signals.
8. Payroll BEC detection signals.
9. Hinglish email parsing and body rendering.
10. .in domain is not automatically malicious.
11. Synthetic .example domain is not automatically malicious.
12. Real pipeline upload validation for IND-01 UPI.
13. Real pipeline upload validation for IND-02 SBI.
14. Real pipeline upload validation for IND-03 Income Tax.
15. Real pipeline upload validation for IND-04, IND-05, IND-06.
16. Campaign correlation on 3-email UPI campaign bundle.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.services.phishing_detector import PhishingDetector
from app.services.threat_intelligence import LocalThreatIntelProvider
from app.services.campaign_detector import CampaignDetectionService

SAMPLES_DIR = Path(__file__).parent.parent / "samples" / "indian"
CAMPAIGN_SAMPLES_DIR = Path(__file__).parent.parent / "samples" / "indian_campaign"


class IndianScenarioTests(unittest.IsolatedAsyncioTestCase):
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
        self.detector = PhishingDetector()
        self.intel = LocalThreatIntelProvider()
        self.campaign_service = CampaignDetectionService()

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)

    # 1. SBI brand impersonation detection
    def test_sbi_brand_impersonation(self) -> None:
        res = self.detector.analyze(
            urls=["https://sbi-netbanking-alert.example/login/verify"],
            sender='"State Bank of India" <alert@sbi-netbanking-alert.example>',
            message="Your SBI Net Banking session has expired. Verify login now.",
        )
        self.assertEqual(res["classification"], "phishing")
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("brand-impersonation-domain", codes)
        self.assertIn("credential-themed-path", codes)

    # 2. HDFC, ICICI, Axis brand detection
    def test_indian_banking_brands(self) -> None:
        for brand, fake_host in [
            ("hdfc", "hdfc-secure-auth.example"),
            ("icici", "icici-customer-portal.example"),
            ("axis", "axis-bank-verify.example"),
        ]:
            res = self.detector.analyze(
                urls=[f"https://{fake_host}/auth/login"],
                sender=f'"Bank Operations" <alert@{fake_host}>',
            )
            codes = [i["code"] for i in res["indicators"]]
            self.assertIn("brand-impersonation-domain", codes, f"Failed for {brand}")

    # 3. Paytm & PhonePe lookalike detection
    def test_paytm_phonepe_brand_detection(self) -> None:
        res_paytm = self.detector.analyze(
            urls=["https://paytm-wallet-verify.example/kyc"],
            sender="kyc@paytm-wallet-verify.example",
        )
        self.assertIn("brand-impersonation-domain", [i["code"] for i in res_paytm["indicators"]])

        res_phonepe = self.detector.analyze(
            urls=["https://phonepe-kyc-alert.example/upi"],
            sender="support@phonepe-kyc-alert.example",
        )
        self.assertIn("brand-impersonation-domain", [i["code"] for i in res_phonepe["indicators"]])

    # 4. UPI keyword and path detection
    def test_upi_path_detection(self) -> None:
        res = self.detector.analyze(
            urls=["https://portal.example/upi/kyc/verify"],
            message="Your UPI service is suspended. Complete KYC.",
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("credential-themed-path", codes)
        self.assertIn("account-suspension-lure", codes)

    # 5. KYC detection signals
    def test_kyc_detection(self) -> None:
        res = self.detector.analyze(
            urls=["https://verify-portal.example/kyc/update"],
            message="Action required: Complete KYC verification within 24 hours.",
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("credential-themed-path", codes)
        self.assertIn("credential-request", codes)
        self.assertIn("urgency-pressure", codes)

    # 6. PAN & Aadhaar detection
    def test_pan_aadhaar_detection(self) -> None:
        res = self.detector.analyze(
            urls=["https://tax-portal.example/pan/aadhaar/link"],
            message="Link your PAN and Aadhaar immediately to avoid account restriction.",
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("credential-themed-path", codes)
        self.assertIn("credential-request", codes)

    # 7. EPFO / UAN detection
    def test_epfo_uan_detection(self) -> None:
        res = self.detector.analyze(
            urls=["https://epfo-portal.example/uan/auth/verify"],
            message="Your UAN account is locked. Verify now.",
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("credential-themed-path", codes)
        self.assertIn("account-suspension-lure", codes)

    # 8. Payroll BEC detection
    def test_payroll_bec_detection(self) -> None:
        res = self.detector.analyze(
            sender='"Rajesh Krishnamurthy" <cfo@corp-hq.example>',
            reply_to="r.krishnamurthy@finance-redirect.example",
            message="Please update my salary account and payroll disbursement details before next cycle. Keep confidential.",
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("reply-to-mismatch", codes)
        self.assertIn("payment-diversion", codes)
        self.assertIn("authority-bypass", codes)

    # 9. Hinglish email parsing and body rendering
    def test_hinglish_body_handling(self) -> None:
        hinglish_text = "Dear Customer, Aapka order hold hai. Abhi verify karein."
        res = self.detector.analyze(
            urls=["https://amazon-india-shipping.example/track/release"],
            message=hinglish_text,
        )
        codes = [i["code"] for i in res["indicators"]]
        self.assertIn("urgency-pressure", codes)
        self.assertIn("account-suspension-lure", codes)

    # 10. .in domain is not automatically malicious
    async def test_in_domain_not_automatically_malicious(self) -> None:
        ti = await self.intel.lookup("mycompany.in", "domain")
        self.assertNotEqual(ti.get("status"), "malicious")
        self.assertIn(ti.get("status"), ["unknown", "benign", "suspicious"])

    # 11. Synthetic .example domain is not automatically malicious
    async def test_example_domain_not_automatically_malicious(self) -> None:
        ti = await self.intel.lookup("corporate-internal.example", "domain")
        self.assertNotEqual(ti.get("status"), "malicious")

    # 12. Real pipeline upload: IND-01 UPI
    def test_real_pipeline_upload_ind01_upi(self) -> None:
        eml_path = SAMPLES_DIR / "ind01_upi_kyc.eml"
        self.assertTrue(eml_path.exists(), f"Missing {eml_path}")
        with open(eml_path, "rb") as f:
            resp = self.client.post(
                "/api/v1/investigate",
                files={"file": ("ind01_upi_kyc.eml", f.read(), "message/rfc822")},
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("email", data)
        self.assertIn("authentication", data)
        self.assertIn("threat_analysis", data)
        self.assertIn("threat_intelligence", data)
        self.assertIn("attack_graph", data)
        self.assertIn("evidence_hash", data)
        self.assertEqual(data["threat_analysis"]["classification"], "Phishing")
        self.assertGreaterEqual(data["threat_analysis"]["confidence_score"], 80)

    # 13. Real pipeline upload: IND-02 SBI
    def test_real_pipeline_upload_ind02_sbi(self) -> None:
        eml_path = SAMPLES_DIR / "ind02_sbi_banking.eml"
        self.assertTrue(eml_path.exists(), f"Missing {eml_path}")
        with open(eml_path, "rb") as f:
            resp = self.client.post(
                "/api/v1/investigate",
                files={"file": ("ind02_sbi_banking.eml", f.read(), "message/rfc822")},
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["threat_analysis"]["classification"], "Phishing")
        self.assertEqual(data["authentication"]["spf"], "fail")

    # 14. Real pipeline upload: IND-03 Income Tax
    def test_real_pipeline_upload_ind03_income_tax(self) -> None:
        eml_path = SAMPLES_DIR / "ind03_income_tax_pan.eml"
        self.assertTrue(eml_path.exists(), f"Missing {eml_path}")
        with open(eml_path, "rb") as f:
            resp = self.client.post(
                "/api/v1/investigate",
                files={"file": ("ind03_income_tax_pan.eml", f.read(), "message/rfc822")},
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["threat_analysis"]["classification"], "Phishing")

    # 15. Real pipeline upload: IND-04, IND-05, IND-06
    def test_real_pipeline_upload_ind04_05_06(self) -> None:
        for fname in ["ind04_epfo_uan.eml", "ind05_hinglish_courier.eml", "ind06_indian_bec.eml"]:
            eml_path = SAMPLES_DIR / fname
            self.assertTrue(eml_path.exists(), f"Missing {eml_path}")
            with open(eml_path, "rb") as f:
                resp = self.client.post(
                    "/api/v1/investigate",
                    files={"file": (fname, f.read(), "message/rfc822")},
                )
            self.assertEqual(resp.status_code, 200, f"Failed for {fname}")
            data = resp.json()
            self.assertIn(data["threat_analysis"]["classification"], ["Phishing", "BEC", "Impersonation"])
            self.assertIn(data["threat_analysis"]["threat_type"], ["Credential Phishing", "Business Email Compromise", "Impersonation"])

    # 16. Campaign correlation on 3-email UPI campaign bundle
    def test_indian_upi_campaign_correlation(self) -> None:
        case_resp = self.client.post("/api/v1/cases", json={"title": "UPI Fraud Campaign Case"}).json()
        case_id = case_resp["id"]

        for fname in ["upi_campaign_01.eml", "upi_campaign_02.eml", "upi_campaign_03.eml"]:
            eml_path = CAMPAIGN_SAMPLES_DIR / fname
            self.assertTrue(eml_path.exists(), f"Missing {eml_path}")
            with open(eml_path, "rb") as f:
                self.client.post(
                    "/api/v1/investigate",
                    data={"case_id": case_id},
                    files={"file": (fname, f.read(), "message/rfc822")},
                )

        detect_resp = self.client.post(f"/api/v1/cases/{case_id}/campaigns/detect")
        self.assertEqual(detect_resp.status_code, 200)
        data = detect_resp.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["campaigns_detected"], 1)
        campaign = data["campaigns"][0]
        self.assertEqual(campaign["email_count"], 3)
        self.assertGreaterEqual(campaign["confidence"], 70)


if __name__ == "__main__":
    unittest.main()
