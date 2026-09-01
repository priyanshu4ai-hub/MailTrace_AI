from __future__ import annotations

import unittest

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import Case, EvidenceLedger
from app.db.session import get_db
from app.main import app
from app.services import case_service, evidence_ledger


class TestEvidenceLedger(unittest.TestCase):
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

    def test_canonical_hash_determinism(self) -> None:
        data1 = {"b": 2, "a": 1, "nested": {"y": "upi://pay?pa=test@sbi", "x": "alert"}}
        data2 = {"a": 1, "nested": {"x": "alert", "y": "upi://pay?pa=test@sbi"}, "b": 2}

        hash1 = evidence_ledger.canonical_hash(data1)
        hash2 = evidence_ledger.canonical_hash(data2)

        self.assertEqual(len(hash1), 64)
        self.assertEqual(hash1, hash2)

    def test_compute_merkle_root(self) -> None:
        # Empty
        self.assertEqual(evidence_ledger.compute_merkle_root([]), "0" * 64)

        # Single hash
        h1 = "a" * 64
        self.assertEqual(evidence_ledger.compute_merkle_root([h1]), h1)

        # 3 hashes (odd count duplicate test)
        h2 = "b" * 64
        h3 = "c" * 64
        root = evidence_ledger.compute_merkle_root([h1, h2, h3])
        self.assertEqual(len(root), 64)
        self.assertNotEqual(root, "0" * 64)

    def test_genesis_and_chain_append(self) -> None:
        # Create a case via API
        resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Forensic Ledger Genesis Test", "severity": "high"},
        )
        self.assertEqual(resp.status_code, 201)
        case_id = resp.json()["id"]

        # Fetch ledger entries directly
        with self.TestingSessionLocal() as db:
            entries = evidence_ledger.get_case_ledger(db, case_id)
            self.assertEqual(len(entries), 2)  # Genesis + CASE_CREATED

            genesis = entries[0]
            self.assertEqual(genesis.sequence_number, 1)
            self.assertEqual(genesis.entry_type, "GENESIS")
            self.assertEqual(genesis.previous_hash, "0" * 64)
            self.assertEqual(len(genesis.entry_hash), 64)

            created_block = entries[1]
            self.assertEqual(created_block.sequence_number, 2)
            self.assertEqual(created_block.entry_type, "CASE_CREATED")
            self.assertEqual(created_block.previous_hash, genesis.entry_hash)
            self.assertEqual(len(created_block.entry_hash), 64)

    def test_verify_intact_ledger_api(self) -> None:
        # Create case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Valid Chain Test", "severity": "medium"},
        )
        case_id = c_resp.json()["id"]

        # Verify via GET /cases/{id}/ledger/verify
        v_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.json()
        self.assertEqual(v_data["status"], "intact")
        self.assertTrue(v_data["is_valid"])
        self.assertEqual(v_data["total_entries"], 2)
        self.assertEqual(v_data["verified_entries"], 2)
        self.assertIsNone(v_data["first_break_at"])
        self.assertIsNotNone(v_data["merkle_root"])

        # Fetch summary via GET /cases/{id}/ledger
        s_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger")
        self.assertEqual(s_resp.status_code, 200)
        s_data = s_resp.json()
        self.assertTrue(s_data["is_valid"])
        self.assertEqual(s_data["total_entries"], 2)
        self.assertEqual(len(s_data["entries"]), 2)

    def test_tamper_detection_data_modification(self) -> None:
        # Create case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Tamper Test Case", "severity": "low"},
        )
        case_id = c_resp.json()["id"]

        # Maliciously modify data_hash of block #2 in the database directly
        with self.TestingSessionLocal() as db:
            entry = db.query(EvidenceLedger).filter(
                EvidenceLedger.case_id == case_id,
                EvidenceLedger.sequence_number == 2,
            ).first()
            self.assertIsNotNone(entry)
            entry.data_hash = "f" * 64  # Fake tampered hash
            db.commit()

        # Run verification
        v_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.json()
        self.assertEqual(v_data["status"], "tampered")
        self.assertFalse(v_data["is_valid"])
        self.assertEqual(v_data["first_break_at"], 2)
        self.assertIn("Entry hash signature invalid", v_data["break_reason"])

    def test_tamper_detection_broken_chain(self) -> None:
        # Create case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Broken Chain Test Case", "severity": "high"},
        )
        case_id = c_resp.json()["id"]

        # Add a note to create block #3
        self.client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "Evidence verified."})

        # Maliciously tamper with previous_hash of block #3
        with self.TestingSessionLocal() as db:
            entry = db.query(EvidenceLedger).filter(
                EvidenceLedger.case_id == case_id,
                EvidenceLedger.sequence_number == 3,
            ).first()
            self.assertIsNotNone(entry)
            entry.previous_hash = "e" * 64  # Bad previous hash
            db.commit()

        # Verify
        v_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.json()
        self.assertEqual(v_data["status"], "tampered")
        self.assertFalse(v_data["is_valid"])
        self.assertEqual(v_data["first_break_at"], 3)
        self.assertIn("Previous hash mismatch", v_data["break_reason"])

    def test_full_investigation_ledger_lifecycle(self) -> None:
        # 1. Create case
        c_resp = self.client.post(
            "/api/v1/cases",
            json={"title": "Full Lifecycle Audit", "severity": "medium"},
        )
        case_id = c_resp.json()["id"]

        # 2. Run email investigation attached to case
        sample_eml = (
            "From: alerts@sbi-secure-update.co.in\n"
            "To: victim@target.in\n"
            "Subject: Immediate Action Required: SBI Account Verification\n"
            "Date: Tue, 01 Sep 2026 10:00:00 +0530\n"
            "Message-ID: <sbi-alert-999@sbi-secure-update.co.in>\n"
            "Authentication-Results: mx.target.in; spf=fail; dkim=fail; dmarc=fail\n\n"
            "Dear Customer, your YONO SBI account is suspended. Update KYC at http://sbi-secure-update.co.in/kyc"
        )
        inv_resp = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("sbi_phish.eml", sample_eml.encode("utf-8"), "message/rfc822")},
        )
        self.assertEqual(inv_resp.status_code, 200)

        # 3. Add analyst note
        self.client.post(f"/api/v1/cases/{case_id}/notes", json={"note": "Confirmed malicious YONO SBI lure."})

        # 4. Update case status
        self.client.patch(f"/api/v1/cases/{case_id}", json={"status": "in_progress", "severity": "critical"})

        # 5. Verify complete ledger chain
        v_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger/verify")
        self.assertEqual(v_resp.status_code, 200)
        v_data = v_resp.json()
        self.assertEqual(v_data["status"], "intact")
        self.assertTrue(v_data["is_valid"])
        self.assertGreaterEqual(v_data["total_entries"], 6)

        # 6. Check summary
        s_resp = self.client.get(f"/api/v1/cases/{case_id}/ledger")
        self.assertEqual(s_resp.status_code, 200)
        s_data = s_resp.json()
        self.assertEqual(s_data["total_entries"], v_data["total_entries"])
        entry_types = [e["entry_type"] for e in s_data["entries"]]
        self.assertIn("GENESIS", entry_types)
        self.assertIn("CASE_CREATED", entry_types)
        self.assertIn("ARTIFACT_STORED", entry_types)
        self.assertIn("INVESTIGATION_SEALED", entry_types)
        self.assertIn("EVIDENCE_SUBMITTED", entry_types)
        self.assertIn("NOTE_ADDED", entry_types)
        self.assertIn("CASE_STATE_CHANGED", entry_types)

    def test_nonexistent_case_404(self) -> None:
        resp = self.client.get("/api/v1/cases/99999/ledger/verify")
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
