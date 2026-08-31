from __future__ import annotations

import unittest

from app.models.schemas import PhishingScanRequest
from app.services.phishing_detector import PhishingDetector


class PhishingDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = PhishingDetector()

    def test_benign_known_domain_stays_low_risk(self) -> None:
        result = self.detector.analyze(
            urls=["https://www.python.org/downloads/"],
            message="The release notes are available at the official website.",
        )

        self.assertEqual(result["classification"], "benign")
        self.assertEqual(result["risk_level"], "safe")
        self.assertLess(result["risk_score"], 10)

    def test_defanged_brand_impersonation_is_high_risk(self) -> None:
        result = self.detector.analyze(
            urls=["hxxps://paypal-security[.]top/verify?next=https%3A%2F%2Fpaypal.com"],
            message="Urgent: verify your account now and enter your password to avoid suspension.",
        )

        codes = {item["code"] for item in result["indicators"]}
        self.assertEqual(result["classification"], "phishing")
        self.assertGreaterEqual(result["risk_score"], 85)
        self.assertIn("url-obfuscation", codes)
        self.assertIn("brand-impersonation-domain", codes)
        self.assertIn("credential-request", codes)

    def test_userinfo_ip_and_reply_to_mismatch_are_detected(self) -> None:
        result = self.detector.analyze(
            urls=["http://microsoft.com@198.51.100.10:8080/login"],
            sender="Microsoft Account <alerts@notice.example>",
            reply_to="replies@evil.example",
        )

        codes = {item["code"] for item in result["indicators"]}
        self.assertEqual(result["classification"], "phishing")
        self.assertIn("userinfo-in-url", codes)
        self.assertIn("ip-address-host", codes)
        self.assertIn("reply-to-mismatch", codes)
        self.assertIn("brand-impersonation-sender", codes)

    def test_account_suspension_with_auth_failures_escalates_to_phishing(self) -> None:
        result = self.detector.analyze(
            message="Urgent: your mailbox will be disabled in 30 minutes. Open the secure portal now.",
            authentication={"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        )

        self.assertEqual(result["classification"], "phishing")
        self.assertGreaterEqual(result["risk_score"], 65)

    def test_request_rejects_empty_content(self) -> None:
        with self.assertRaises(ValueError):
            PhishingScanRequest()

    def test_defanged_links_are_extracted_from_text(self) -> None:
        links = self.detector.extract_urls("Review hxxp[:]//verify-account[.]example[.]top/login immediately.")

        self.assertEqual(links, ["http://verify-account.example.top/login"])

    def test_mismatched_visible_html_link_is_high_risk(self) -> None:
        result = self.detector.analyze(
            message="Review your account statement.",
            link_mismatches=["paypal.com -> credential-check.example.top"],
        )

        self.assertEqual(result["classification"], "suspicious")
        self.assertIn("visible-link-mismatch", {item["code"] for item in result["indicators"]})

    def test_integer_and_hex_ip_hosts_are_treated_as_ip_destinations(self) -> None:
        result = self.detector.analyze(urls=["https://0x7f000001/login", "https://2130706433/login"])

        self.assertIn("ip-address-host", {item["code"] for item in result["indicators"]})


if __name__ == "__main__":
    unittest.main()
