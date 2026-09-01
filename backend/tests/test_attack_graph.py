"""Tests for Case 5: Forensic Attack Graph & Infrastructure Topology."""

from __future__ import annotations

import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.routes import _build_attack_graph
from app.db.base import Base
from app.db.session import get_db
from app.main import app

SAMPLE_EML_MULTI_HOP = """From: "Security Operations" <alert@login-targetcorp-auth.com>
To: target.user@target.com
Subject: URGENT: Password Verification
Date: Tue, 01 Sep 2026 10:00:00 +0000
Message-ID: <graph-001@login-targetcorp-auth.com>
Received: from mx-in.target.com (mx-in.target.com [203.0.113.50]) by mailstore.target.com; Tue, 01 Sep 2026 10:00:02 +0000
Received: from intermediate.relay.net (intermediate.relay.net [185.220.101.45]) by mx-in.target.com; Tue, 01 Sep 2026 10:00:01 +0000
Received: from origin.attacker.org (origin.attacker.org [198.51.100.22]) by intermediate.relay.net; Tue, 01 Sep 2026 10:00:00 +0000
Authentication-Results: mx.target.com; spf=fail; dkim=none; dmarc=fail

Please verify credentials at https://login-targetcorp-auth.com/auth/login and track at https://track.evil.org/click
"""


class AttackGraphTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)

    # 1. Sequential relay hop ordering (Origin -> Intermediate -> Delivery)
    def test_sequential_relay_hop_ordering(self) -> None:
        email_data = {
            "from": "alice@sender.com",
            "to": "bob@recipient.com",
            "message_id": "<test-seq-001>",
            "subject": "Test Sequence",
            "received_headers": [
                "from mx.dest.com (203.0.113.50) by mail.dest.com",     # Most recent (Gateway)
                "from relay.mid.com (185.220.101.45) by mx.dest.com",   # Intermediate
                "from origin.src.com (198.51.100.22) by relay.mid.com", # Origin
            ],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Safe", "confidence_score": 90},
        )
        links = graph["links"]

        # Origin IP (198.51.100.22) should relay to Intermediate IP (185.220.101.45)
        relayed_links = [l for l in links if l["relation"] == "RELAYED_TO"]
        self.assertEqual(len(relayed_links), 2)
        self.assertEqual(relayed_links[0]["source"], "ip:198.51.100.22")
        self.assertEqual(relayed_links[0]["target"], "ip:185.220.101.45")
        self.assertEqual(relayed_links[1]["source"], "ip:185.220.101.45")
        self.assertEqual(relayed_links[1]["target"], "ip:203.0.113.50")

    # 2. Relay chain generation (ORIGINATES_FROM, RELAYED_TO, DELIVERED_VIA)
    def test_relay_chain_relations(self) -> None:
        email_data = {
            "from": "alice@sender.com",
            "to": "bob@recipient.com",
            "message_id": "<test-seq-002>",
            "received_headers": [
                "from mx.dest.com (203.0.113.50) by mail.dest.com",
                "from origin.src.com (198.51.100.22) by mx.dest.com",
            ],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Safe"},
        )
        relations = [l["relation"] for l in graph["links"]]
        self.assertIn("ORIGINATES_FROM", relations)
        self.assertIn("RELAYED_TO", relations)
        self.assertIn("DELIVERED_VIA", relations)

    # 3. Duplicate relay IP handling (unique node IDs and unique links)
    def test_duplicate_relay_ip_handling(self) -> None:
        email_data = {
            "from": "user@sender.com",
            "to": "target@domain.com",
            "message_id": "<test-dup-001>",
            "received_headers": [
                "from hop1 (198.51.100.22) by dest",
                "from hop2 (198.51.100.22) by hop1",  # Same IP repeated
            ],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Safe"},
        )
        node_ids = [n["id"] for n in graph["nodes"]]
        self.assertEqual(node_ids.count("ip:198.51.100.22"), 1)

    # 4. Domain node generation
    def test_domain_node_generation(self) -> None:
        email_data = {
            "from": "attacker@evil-domain.com",
            "to": "victim@corporate.com",
            "message_id": "<test-domain-001>",
            "received_headers": [],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "fail"},
            geo_hops=[],
            threat_analysis={"classification": "Suspicious"},
        )
        domain_nodes = [n for n in graph["nodes"] if n["type"] == "domain"]
        self.assertEqual(len(domain_nodes), 1)
        self.assertEqual(domain_nodes[0]["id"], "domain:evil-domain.com")

    # 5. URL -> Domain relationship (HOSTED_ON)
    def test_url_domain_relationship(self) -> None:
        email_data = {
            "from": "legit@corp.com",
            "to": "user@corp.com",
            "message_id": "<test-url-001>",
            "received_headers": [],
            "urls": ["https://login-portal.phish.com/sso"],
        }
        threat_intel = [
            {
                "indicator": "https://login-portal.phish.com/sso",
                "type": "url",
                "status": "malicious",
                "confidence": 95,
            },
            {
                "indicator": "login-portal.phish.com",
                "type": "domain",
                "status": "malicious",
                "confidence": 95,
            },
        ]
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Phishing"},
            threat_intelligence=threat_intel,
        )
        url_domain_links = [l for l in graph["links"] if l["relation"] == "HOSTED_ON"]
        self.assertEqual(len(url_domain_links), 1)
        self.assertEqual(url_domain_links[0]["source"], "url:https://login-portal.phish.com/sso")
        self.assertEqual(url_domain_links[0]["target"], "domain:login-portal.phish.com")

    # 6. Sender -> Domain relationship (BELONGS_TO_DOMAIN)
    def test_sender_domain_relationship(self) -> None:
        email_data = {
            "from": "ceo@targetcorp-spoof.org",
            "to": "finance@target.com",
            "message_id": "<test-sender-001>",
            "received_headers": [],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "fail"},
            geo_hops=[],
            threat_analysis={"classification": "BEC"},
        )
        sender_domain_links = [l for l in graph["links"] if l["relation"] == "BELONGS_TO_DOMAIN"]
        self.assertEqual(len(sender_domain_links), 1)
        self.assertEqual(sender_domain_links[0]["source"], "sender:ceo@targetcorp-spoof.org")
        self.assertEqual(sender_domain_links[0]["target"], "domain:targetcorp-spoof.org")

    # 7. Threat intelligence propagation onto nodes
    def test_threat_intelligence_propagation(self) -> None:
        email_data = {
            "from": "alert@phish.com",
            "to": "user@corp.com",
            "message_id": "<test-intel-001>",
            "received_headers": ["from (198.51.100.22) by dest"],
            "urls": ["http://phish.com/login"],
        }
        threat_intel = [
            {"indicator": "alert@phish.com", "type": "email", "status": "suspicious", "confidence": 75, "source": "Local Analysis"},
            {"indicator": "198.51.100.22", "type": "ip", "status": "malicious", "confidence": 90, "source": "AbuseIPDB"},
            {"indicator": "http://phish.com/login", "type": "url", "status": "malicious", "confidence": 96, "source": "Local Analysis"},
        ]
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "fail"},
            geo_hops=[{"ip": "198.51.100.22", "country": "RU", "city": "Moscow"}],
            threat_analysis={"classification": "Phishing", "risk_level": "critical"},
            threat_intelligence=threat_intel,
        )
        nodes_dict = {n["id"]: n for n in graph["nodes"]}
        self.assertEqual(nodes_dict["ip:198.51.100.22"]["status"], "malicious")
        self.assertEqual(nodes_dict["ip:198.51.100.22"]["confidence"], 90)
        self.assertEqual(nodes_dict["url:http://phish.com/login"]["status"], "malicious")
        self.assertEqual(nodes_dict["url:http://phish.com/login"]["confidence"], 96)

    # 8. Graph generation with no URLs
    def test_graph_with_no_urls(self) -> None:
        email_data = {
            "from": "user@internal.org",
            "to": "team@internal.org",
            "message_id": "<test-no-url-001>",
            "received_headers": [],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Safe"},
        )
        url_nodes = [n for n in graph["nodes"] if n["type"] == "url"]
        self.assertEqual(len(url_nodes), 0)

    # 9. Graph generation with no relay IPs
    def test_graph_with_no_relay_ips(self) -> None:
        email_data = {
            "from": "direct@sender.com",
            "to": "direct@recipient.com",
            "message_id": "<test-no-ip-001>",
            "received_headers": [],
            "urls": [],
        }
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "pass"},
            geo_hops=[],
            threat_analysis={"classification": "Safe"},
        )
        # Should link sender directly to email
        sent_links = [l for l in graph["links"] if l["relation"] == "SENT"]
        self.assertEqual(len(sent_links), 1)

    # 10. Graph generation with multiple URLs
    def test_graph_with_multiple_urls(self) -> None:
        email_data = {
            "from": "spammer@domain.com",
            "to": "user@corp.com",
            "message_id": "<test-multi-url-001>",
            "received_headers": [],
            "urls": ["http://url1.com", "http://url2.com"],
        }
        threat_intel = [
            {"indicator": "http://url1.com", "type": "url", "status": "suspicious", "confidence": 70},
            {"indicator": "http://url2.com", "type": "url", "status": "malicious", "confidence": 95},
        ]
        graph = _build_attack_graph(
            email_data=email_data,
            authentication={"spf": "fail"},
            geo_hops=[],
            threat_analysis={"classification": "Phishing"},
            threat_intelligence=threat_intel,
        )
        url_nodes = [n for n in graph["nodes"] if n["type"] == "url"]
        self.assertEqual(len(url_nodes), 2)

    # 11. Graph generation in stateless mode
    def test_graph_in_stateless_mode(self) -> None:
        resp = self.client.post(
            "/api/v1/investigate",
            files={"file": ("test.eml", SAMPLE_EML_MULTI_HOP.encode(), "message/rfc822")},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("attack_graph", data)
        graph = data["attack_graph"]
        self.assertTrue(len(graph["nodes"]) >= 5)
        self.assertTrue(len(graph["links"]) >= 4)

    # 12. Graph generation in case mode & timeline recording
    def test_graph_in_case_mode_and_timeline_event(self) -> None:
        case_id = self.client.post("/api/v1/cases", json={"title": "Graph Case Test"}).json()["id"]
        resp = self.client.post(
            "/api/v1/investigate",
            data={"case_id": case_id},
            files={"file": ("test.eml", SAMPLE_EML_MULTI_HOP.encode(), "message/rfc822")},
        )
        self.assertEqual(resp.status_code, 200)

        # Verify timeline recorded ATTACK_GRAPH_GENERATED with node count metadata
        tl = self.client.get(f"/api/v1/cases/{case_id}/timeline").json()
        graph_events = [e for e in tl["events"] if e["event_type"] == "ATTACK_GRAPH_GENERATED"]
        self.assertEqual(len(graph_events), 1)
        meta = graph_events[0].get("event_metadata") or graph_events[0].get("metadata") or {}
        if isinstance(meta, str):
            import json
            meta = json.loads(meta)
        self.assertGreater(meta.get("node_count", 0), 0)


if __name__ == "__main__":
    unittest.main()
