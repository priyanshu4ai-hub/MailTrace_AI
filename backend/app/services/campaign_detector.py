"""
MailTrace AI — Case 6: Campaign Detection & Multi-Email Correlation Service.

Provides deterministic IOC correlation, explainable pairwise scoring,
cluster identification, unified attack graph synthesis, and defensive recommendations.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


class CampaignDetectionService:
    """Multi-email correlation and attack campaign detection engine."""

    _MIN_CAMPAIGN_SIZE = 2
    _CORRELATION_THRESHOLD = 30
    _HIGH_CONFIDENCE_THRESHOLD = 85

    # Weights table for explainable scoring
    WEIGHTS = {
        "SAME_URL": 30,
        "SHARED_MALICIOUS_DOMAIN": 25,
        "SHARED_IP": 25,
        "SAME_SENDER_DOMAIN": 20,
        "SAME_REPLY_TO": 20,
        "SHARED_THREAT_INTEL": 20,
        "SHARED_INFRASTRUCTURE": 20,
        "SUBJECT_SIMILARITY": 10,
        "SAME_THREAT_TYPE": 10,
    }

    def detect_campaigns(
        self,
        email_items: list[dict[str, Any]],
        case_id: int | None = None,
    ) -> dict[str, Any]:
        """Runs multi-email correlation across a list of normalized email artifact records."""
        if len(email_items) < self._MIN_CAMPAIGN_SIZE:
            return {
                "status": "insufficient_data",
                "emails_analyzed": len(email_items),
                "campaigns_detected": 0,
                "high_confidence_campaigns": 0,
                "shared_iocs": 0,
                "campaigns": [],
                "message": "At least 2 email artifacts are required to detect attack campaigns.",
            }

        # 1. Feature Extraction & Normalization
        features = [self._extract_features(e) for e in email_items]

        # 2. Build Inverted Indexes for O(N) candidate matching
        indexes = self._build_inverted_indexes(features)

        # 3. Pairwise Correlation Calculation
        candidate_pairs = self._find_candidate_pairs(features, indexes)
        correlations: list[dict[str, Any]] = []
        adjacency: dict[int, dict[int, dict[str, Any]]] = defaultdict(dict)

        for id_a, id_b in candidate_pairs:
            f_a = next(f for f in features if f["id"] == id_a)
            f_b = next(f for f in features if f["id"] == id_b)
            pair_result = self._score_pair(f_a, f_b)

            if pair_result["score"] >= self._CORRELATION_THRESHOLD:
                correlations.append(pair_result)
                adjacency[id_a][id_b] = pair_result
                adjacency[id_b][id_a] = pair_result

        # 4. Connected Component Clustering
        clusters = self._cluster_connected_components(features, adjacency)

        if not clusters:
            return {
                "status": "no_campaigns_detected",
                "emails_analyzed": len(email_items),
                "campaigns_detected": 0,
                "high_confidence_campaigns": 0,
                "shared_iocs": 0,
                "campaigns": [],
                "message": "Analyzed emails do not share sufficient correlation signals to form an attack campaign.",
            }

        # 5. Assemble Campaign Profiles
        campaigns = []
        year = datetime.now(timezone.utc).year
        total_shared_iocs = 0

        for idx, cluster_ids in enumerate(clusters, start=1):
            camp_id = f"MT-CAMP-{year}-{idx:04d}"
            cluster_features = [f for f in features if f["id"] in cluster_ids]
            cluster_correlations = [
                c for c in correlations
                if c["source_email_id"] in cluster_ids and c["target_email_id"] in cluster_ids
            ]

            profile = self._build_campaign_profile(
                campaign_id=camp_id,
                case_id=case_id,
                cluster_features=cluster_features,
                cluster_correlations=cluster_correlations,
            )
            total_shared_iocs += profile["shared_ioc_count"]
            campaigns.append(profile)

        high_conf_count = sum(1 for c in campaigns if c["confidence"] >= self._HIGH_CONFIDENCE_THRESHOLD)

        return {
            "status": "completed",
            "emails_analyzed": len(email_items),
            "campaigns_detected": len(campaigns),
            "high_confidence_campaigns": high_conf_count,
            "shared_iocs": total_shared_iocs,
            "campaigns": campaigns,
            "message": f"Successfully correlated {len(email_items)} emails into {len(campaigns)} campaign(s).",
        }

    # ── Feature Extraction ──────────────────────────────────────────

    def _extract_features(self, item: dict[str, Any]) -> dict[str, Any]:
        """Extracts normalized IOCs, metadata, and threat features from email artifact / investigation result."""
        artifact_id = item.get("id") or item.get("artifact_id") or 0
        case_id = item.get("case_id")
        subject = item.get("subject", "").strip()
        sender = item.get("sender", "") or item.get("from", "")
        recipient = item.get("recipient", "") or item.get("to", "")
        date_str = item.get("created_at") or item.get("date") or ""

        # Parse nested investigation payload if present
        payload = item.get("payload") or item.get("investigation") or {}
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}

        threat_analysis = payload.get("threat_analysis") or item.get("threat_analysis") or {}
        threat_intel = payload.get("threat_intelligence") or item.get("threat_intelligence") or []
        geo_hops = payload.get("geo_hops") or item.get("geo_hops") or []
        auth = payload.get("authentication") or item.get("authentication") or {}

        # Senders and domains
        sender_clean = self._extract_email_addr(sender)
        sender_domain = sender_clean.split("@")[-1].lower() if "@" in sender_clean else ""

        reply_to = item.get("reply_to") or payload.get("email", {}).get("reply_to", "")
        reply_to_clean = self._extract_email_addr(reply_to)

        # URLs
        raw_urls = item.get("urls") or payload.get("email", {}).get("urls", [])
        normalized_urls = set()
        url_domains = set()
        for u in raw_urls:
            if u:
                norm_u = self._normalize_url(u)
                if norm_u:
                    normalized_urls.add(norm_u)
                    dom = self._url_to_domain(norm_u)
                    if dom:
                        url_domains.add(dom)

        # IPs from Received headers & GeoHops
        ips = set()
        asns = set()
        isps = set()
        for hop in geo_hops:
            if hop.get("ip"):
                ips.add(hop["ip"].strip())
            if hop.get("asn") and hop["asn"] != "Unknown":
                asns.add(hop["asn"].strip())
            if hop.get("isp") and hop["isp"] != "Unknown":
                isps.add(hop["isp"].strip())

        rec_headers = item.get("received_headers") or payload.get("email", {}).get("received_headers", [])
        for hdr in rec_headers:
            for candidate in re.findall(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", hdr):
                ips.add(candidate)

        # Threat classification
        threat_type = (
            threat_analysis.get("threat_type")
            or threat_analysis.get("classification")
            or item.get("verdict")
            or "Unknown"
        )
        risk_score = threat_analysis.get("confidence_score", threat_analysis.get("confidence", item.get("risk_score", 0)))

        # Intel indicators map
        intel_iocs = {
            i.get("indicator", "").lower().strip(): i
            for i in threat_intel
            if i.get("indicator")
        }

        return {
            "id": artifact_id,
            "case_id": case_id,
            "subject": subject,
            "sender": sender_clean,
            "sender_domain": sender_domain,
            "reply_to": reply_to_clean,
            "recipient": recipient,
            "date": str(date_str),
            "urls": normalized_urls,
            "url_domains": url_domains,
            "all_domains": (url_domains | ({sender_domain} if sender_domain else set())),
            "ips": ips,
            "asns": asns,
            "isps": isps,
            "threat_type": threat_type,
            "risk_score": risk_score,
            "intel_iocs": intel_iocs,
            "auth": auth,
            "raw_item": item,
        }

    # ── Inverted Indexing ───────────────────────────────────────────

    def _build_inverted_indexes(self, features: list[dict[str, Any]]) -> dict[str, dict[str, set[int]]]:
        """Constructs fast inverted lookup tables mapping indicators to email IDs."""
        indexes: dict[str, dict[str, set[int]]] = {
            "url": defaultdict(set),
            "domain": defaultdict(set),
            "ip": defaultdict(set),
            "sender_domain": defaultdict(set),
            "reply_to": defaultdict(set),
            "asn": defaultdict(set),
            "intel_ioc": defaultdict(set),
        }

        for f in features:
            eid = f["id"]
            for u in f["urls"]:
                indexes["url"][u].add(eid)
            for d in f["all_domains"]:
                indexes["domain"][d].add(eid)
            for ip in f["ips"]:
                indexes["ip"][ip].add(eid)
            if f["sender_domain"]:
                indexes["sender_domain"][f["sender_domain"]].add(eid)
            if f["reply_to"]:
                indexes["reply_to"][f["reply_to"]].add(eid)
            for asn in f["asns"]:
                indexes["asn"][asn].add(eid)
            for ioc in f["intel_iocs"]:
                indexes["intel_ioc"][ioc].add(eid)

        return indexes

    def _find_candidate_pairs(
        self,
        features: list[dict[str, Any]],
        indexes: dict[str, dict[str, set[int]]],
    ) -> set[tuple[int, int]]:
        """Identifies pairs of emails that share at least one index entry to avoid full O(N^2) comparison."""
        candidate_pairs: set[tuple[int, int]] = set()

        for category, table in indexes.items():
            for _, email_set in table.items():
                if len(email_set) >= 2:
                    email_list = sorted(list(email_set))
                    for i in range(len(email_list)):
                        for j in range(i + 1, len(email_list)):
                            candidate_pairs.add((email_list[i], email_list[j]))

        # Also add subject-similar candidate pairs if not already linked
        for i in range(len(features)):
            for j in range(i + 1, len(features)):
                pair = (features[i]["id"], features[j]["id"])
                if pair not in candidate_pairs:
                    sim = self._subject_similarity(features[i]["subject"], features[j]["subject"])
                    if sim >= 0.6:
                        candidate_pairs.add(pair)

        return candidate_pairs

    # ── Explainable Pairwise Scoring ────────────────────────────────

    def _score_pair(self, f_a: dict[str, Any], f_b: dict[str, Any]) -> dict[str, Any]:
        """Calculates pairwise correlation score based on shared forensic signals."""
        signals: list[dict[str, Any]] = []
        reasons: list[str] = []
        score = 0

        # 1. Exact URL Match (+30)
        shared_urls = f_a["urls"] & f_b["urls"]
        if shared_urls:
            weight = self.WEIGHTS["SAME_URL"]
            score += weight
            sample_url = next(iter(shared_urls))
            signals.append({
                "signal": "SAME_URL",
                "weight": weight,
                "detail": f"Exact matching URL: {sample_url}" if len(shared_urls) == 1 else f"{len(shared_urls)} identical URLs shared",
            })
            reasons.append(f"Shared identical payload destination: {sample_url}")

        # 2. Shared Domain (+25)
        shared_domains = (f_a["url_domains"] & f_b["url_domains"]) or (f_a["all_domains"] & f_b["all_domains"])
        if shared_domains:
            weight = self.WEIGHTS["SHARED_MALICIOUS_DOMAIN"]
            score += weight
            sample_dom = next(iter(shared_domains))
            signals.append({
                "signal": "SHARED_MALICIOUS_DOMAIN",
                "weight": weight,
                "detail": f"Shared domain infrastructure: {sample_dom}",
            })
            reasons.append(f"Shared target infrastructure domain: {sample_dom}")

        # 3. Shared Relay IP (+25)
        shared_ips = f_a["ips"] & f_b["ips"]
        if shared_ips:
            weight = self.WEIGHTS["SHARED_IP"]
            score += weight
            sample_ip = next(iter(shared_ips))
            signals.append({
                "signal": "SHARED_IP",
                "weight": weight,
                "detail": f"Shared MTA relay IP: {sample_ip}",
            })
            reasons.append(f"Shared originating or relay transport IP: {sample_ip}")

        # 4. Same Sender Domain (+20)
        if f_a["sender_domain"] and f_a["sender_domain"] == f_b["sender_domain"]:
            weight = self.WEIGHTS["SAME_SENDER_DOMAIN"]
            score += weight
            signals.append({
                "signal": "SAME_SENDER_DOMAIN",
                "weight": weight,
                "detail": f"Identical sender domain: @{f_a['sender_domain']}",
            })
            reasons.append(f"Matching envelope sender domain: @{f_a['sender_domain']}")

        # 5. Same Reply-To Header (+20)
        if f_a["reply_to"] and f_a["reply_to"] == f_b["reply_to"]:
            weight = self.WEIGHTS["SAME_REPLY_TO"]
            score += weight
            signals.append({
                "signal": "SAME_REPLY_TO",
                "weight": weight,
                "detail": f"Identical Reply-To address: {f_a['reply_to']}",
            })
            reasons.append(f"Identical exfiltration/response Reply-To header: {f_a['reply_to']}")

        # 6. Shared Threat Intelligence IOC (+20)
        shared_intel_keys = set(f_a["intel_iocs"].keys()) & set(f_b["intel_iocs"].keys())
        if shared_intel_keys:
            weight = self.WEIGHTS["SHARED_THREAT_INTEL"]
            score += weight
            sample_ioc = next(iter(shared_intel_keys))
            signals.append({
                "signal": "SHARED_THREAT_INTEL",
                "weight": weight,
                "detail": f"Correlated threat intelligence indicator: {sample_ioc}",
            })
            reasons.append(f"Correlated threat intelligence indicator: {sample_ioc}")

        # 7. Shared Autonomous System / ISP Infrastructure (+20)
        shared_asns = f_a["asns"] & f_b["asns"]
        if shared_asns and not shared_ips:  # Avoid redundant weight if IP already matched
            weight = self.WEIGHTS["SHARED_INFRASTRUCTURE"]
            score += weight
            sample_asn = next(iter(shared_asns))
            signals.append({
                "signal": "SHARED_INFRASTRUCTURE",
                "weight": weight,
                "detail": f"Shared Autonomous System: {sample_asn}",
            })
            reasons.append(f"Originating from identical ASN: {sample_asn}")

        # 8. Subject Pattern Similarity (+10)
        subj_sim = self._subject_similarity(f_a["subject"], f_b["subject"])
        if subj_sim >= 0.5:
            weight = self.WEIGHTS["SUBJECT_SIMILARITY"]
            score += weight
            signals.append({
                "signal": "SUBJECT_SIMILARITY",
                "weight": weight,
                "detail": f"Subject lure pattern similarity: {int(subj_sim * 100)}%",
            })
            reasons.append(f"Lure subject similarity ({int(subj_sim * 100)}% match)")

        # 9. Matching Threat Classification (+10)
        if (
            f_a["threat_type"]
            and f_a["threat_type"] != "Unknown"
            and f_a["threat_type"].lower() == f_b["threat_type"].lower()
        ):
            weight = self.WEIGHTS["SAME_THREAT_TYPE"]
            score += weight
            signals.append({
                "signal": "SAME_THREAT_TYPE",
                "weight": weight,
                "detail": f"Matching attack classification: {f_a['threat_type']}",
            })

        # Cap score at 100
        final_score = min(100, score)

        return {
            "source_email_id": f_a["id"],
            "target_email_id": f_b["id"],
            "score": final_score,
            "signals": signals,
            "reasons": reasons,
        }

    # ── Clustering & Profile Synthesis ──────────────────────────────

    def _cluster_connected_components(
        self,
        features: list[dict[str, Any]],
        adjacency: dict[int, dict[int, dict[str, Any]]],
    ) -> list[list[int]]:
        """Groups emails into campaign clusters using graph connected components."""
        visited: set[int] = set()
        clusters: list[list[int]] = []

        all_ids = [f["id"] for f in features if f["id"] in adjacency]

        for eid in all_ids:
            if eid not in visited:
                cluster = []
                queue = [eid]
                visited.add(eid)

                while queue:
                    curr = queue.pop(0)
                    cluster.append(curr)
                    for neighbor, edge in adjacency.get(curr, {}).items():
                        if edge["score"] >= self._CORRELATION_THRESHOLD and neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

                if len(cluster) >= self._MIN_CAMPAIGN_SIZE:
                    clusters.append(sorted(cluster))

        return clusters

    def _build_campaign_profile(
        self,
        campaign_id: str,
        case_id: int | None,
        cluster_features: list[dict[str, Any]],
        cluster_correlations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Constructs full campaign profile including members, shared IOCs, graph, and recommendations."""
        email_members: list[dict[str, Any]] = []
        for f in cluster_features:
            email_members.append({
                "artifact_id": f["id"],
                "case_id": f["case_id"] or case_id,
                "subject": f["subject"],
                "sender": f["sender"],
                "recipient": f["recipient"],
                "date": f["date"],
                "risk_score": f["risk_score"],
                "threat_type": f["threat_type"],
                "related_ioc_count": len(f["urls"]) + len(f["all_domains"]) + len(f["ips"]),
            })

        # Calculate overall campaign confidence (average of active pairwise correlations, maxed with member risk)
        pair_scores = [c["score"] for c in cluster_correlations] if cluster_correlations else [70]
        avg_corr = sum(pair_scores) / len(pair_scores) if pair_scores else 70
        confidence = min(100, int(avg_corr))

        # Collect and count shared indicators (seen in >= 2 emails in the cluster)
        url_counts = defaultdict(set)
        domain_counts = defaultdict(set)
        ip_counts = defaultdict(set)
        sender_dom_counts = defaultdict(set)

        for f in cluster_features:
            eid = f["id"]
            for u in f["urls"]:
                url_counts[u].add(eid)
            for d in f["all_domains"]:
                domain_counts[d].add(eid)
            for ip in f["ips"]:
                ip_counts[ip].add(eid)
            if f["sender_domain"]:
                sender_dom_counts[f["sender_domain"]].add(eid)

        shared_indicators: list[dict[str, Any]] = []

        for u, eids in url_counts.items():
            if len(eids) >= 2:
                shared_indicators.append({
                    "indicator": u,
                    "type": "url",
                    "emails_count": len(eids),
                    "emails_seen": sorted(list(eids)),
                    "status": "malicious",
                    "confidence": 95,
                    "source": "Campaign Correlation",
                    "reasons": [f"Shared credential/payload destination across {len(eids)} correlated messages"],
                })

        for d, eids in domain_counts.items():
            if len(eids) >= 2:
                shared_indicators.append({
                    "indicator": d,
                    "type": "domain",
                    "emails_count": len(eids),
                    "emails_seen": sorted(list(eids)),
                    "status": "suspicious",
                    "confidence": 90,
                    "source": "Campaign Correlation",
                    "reasons": [f"Shared infrastructure domain resolved across {len(eids)} correlated messages"],
                })

        for ip, eids in ip_counts.items():
            if len(eids) >= 2:
                shared_indicators.append({
                    "indicator": ip,
                    "type": "ip",
                    "emails_count": len(eids),
                    "emails_seen": sorted(list(eids)),
                    "status": "suspicious",
                    "confidence": 85,
                    "source": "Campaign Correlation",
                    "reasons": [f"Shared MTA relay transport IP across {len(eids)} correlated messages"],
                })

        for s_dom, eids in sender_dom_counts.items():
            if len(eids) >= 2 and not any(i["indicator"] == s_dom for i in shared_indicators):
                shared_indicators.append({
                    "indicator": s_dom,
                    "type": "sender_domain",
                    "emails_count": len(eids),
                    "emails_seen": sorted(list(eids)),
                    "status": "suspicious",
                    "confidence": 80,
                    "source": "Campaign Correlation",
                    "reasons": [f"Shared sender domain pattern across {len(eids)} messages"],
                })

        # Distinct infrastructure count (domains + IPs)
        shared_infra_count = len([i for i in shared_indicators if i["type"] in ("domain", "ip")])

        # Determine dominant Campaign Threat Type & Name
        threat_types = [f["threat_type"] for f in cluster_features if f["threat_type"] != "Unknown"]
        threat_type_counts = defaultdict(int)
        for tt in threat_types:
            threat_type_counts[tt] += 1

        primary_threat = (
            max(threat_type_counts.items(), key=lambda x: x[1])[0]
            if threat_type_counts
            else "Credential Phishing"
        )
        if "phish" in primary_threat.lower():
            campaign_name = "Credential Phishing Campaign"
        elif "bec" in primary_threat.lower() or "compromise" in primary_threat.lower():
            campaign_name = "Business Email Compromise Campaign"
        elif "malware" in primary_threat.lower():
            campaign_name = "Malware Delivery Campaign"
        elif "impersonation" in primary_threat.lower():
            campaign_name = "Brand Impersonation Campaign"
        else:
            campaign_name = "Coordinated Threat Campaign"

        # Unique why reasons
        all_reasons = []
        for c in cluster_correlations:
            all_reasons.extend(c["reasons"])
        unique_reasons = list(dict.fromkeys(all_reasons))[:6]

        # Defensive Recommendations
        recommendations = self._generate_campaign_recommendations(shared_indicators, primary_threat)

        # Multi-email Attack Graph Synthesis
        campaign_graph = self._build_campaign_attack_graph(cluster_features, shared_indicators)

        # Deterministic / AI narrative summary
        ai_summary = self._generate_summary(campaign_name, len(cluster_features), shared_indicators, unique_reasons)

        now_str = datetime.now(timezone.utc).isoformat()

        return {
            "campaign_id": campaign_id,
            "case_id": case_id,
            "name": campaign_name,
            "status": "detected",
            "confidence": confidence,
            "threat_type": primary_threat,
            "email_count": len(cluster_features),
            "shared_ioc_count": len(shared_indicators),
            "shared_infrastructure_count": shared_infra_count,
            "emails": email_members,
            "shared_indicators": shared_indicators,
            "correlations": cluster_correlations,
            "reasons": unique_reasons,
            "recommendations": recommendations,
            "ai_summary": ai_summary,
            "attack_graph": campaign_graph,
            "created_at": now_str,
            "updated_at": now_str,
        }

    # ── Campaign Attack Graph Generator ─────────────────────────────

    def _build_campaign_attack_graph(
        self,
        cluster_features: list[dict[str, Any]],
        shared_indicators: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        """Synthesizes a converged attack graph displaying multi-email infrastructure correlation."""
        nodes: dict[str, dict[str, Any]] = {}
        links: list[dict[str, Any]] = []
        seen_links: set[tuple[str, str, str]] = set()

        def add_node(node: dict[str, Any]) -> None:
            if node["id"] not in nodes:
                nodes[node["id"]] = node

        def add_link(src: str, tgt: str, rel: str) -> None:
            key = (src, tgt, rel)
            if key not in seen_links and src in nodes and tgt in nodes:
                seen_links.add(key)
                links.append({"source": src, "target": tgt, "relation": rel})

        # Add shared indicator nodes first (these act as convergence hubs)
        for ind in shared_indicators:
            node_id = f"{ind['type']}:{ind['indicator']}"
            node_type = "url" if ind["type"] == "url" else "relay_ip" if ind["type"] == "ip" else "domain"
            add_node({
                "id": node_id,
                "name": f"[SHARED] {ind['indicator'][:35]}",
                "type": node_type,
                "status": ind["status"],
                "confidence": ind["confidence"],
                "source": "Campaign Correlation",
                "reasons": ind["reasons"],
            })

        # Add email member nodes and connect them to shared entities
        for f in cluster_features:
            email_node_id = f"email:artifact-{f['id']}"
            add_node({
                "id": email_node_id,
                "name": f"Email #{f['id']}: {f['subject'][:30]}...",
                "type": "email",
                "status": "malicious" if f["risk_score"] >= 70 else "suspicious",
                "confidence": f["risk_score"],
            })

            # Connect to sender domain node
            if f["sender_domain"]:
                dom_node_id = f"domain:{f['sender_domain']}"
                add_node({
                    "id": dom_node_id,
                    "name": f["sender_domain"],
                    "type": "domain",
                    "status": "suspicious",
                    "confidence": 80,
                })
                add_link(email_node_id, dom_node_id, "SENDER_DOMAIN")

            # Connect to shared URLs
            for u in f["urls"]:
                url_node_id = f"url:{u}"
                if url_node_id in nodes:
                    add_link(email_node_id, url_node_id, "EMBEDS_SHARED_URL")

            # Connect to shared domains
            for d in f["url_domains"]:
                dom_node_id = f"domain:{d}"
                if dom_node_id in nodes:
                    add_link(email_node_id, dom_node_id, "HOSTED_ON_SHARED_DOMAIN")

            # Connect to shared IPs
            for ip in f["ips"]:
                ip_node_id = f"ip:{ip}"
                if ip_node_id in nodes:
                    add_link(email_node_id, ip_node_id, "RELAYED_VIA_SHARED_IP")

        return {"nodes": list(nodes.values()), "links": links}

    # ── Helpers ─────────────────────────────────────────────────────

    def _generate_campaign_recommendations(
        self,
        shared_indicators: list[dict[str, Any]],
        threat_type: str,
    ) -> list[str]:
        recs = []
        domains = [i["indicator"] for i in shared_indicators if i["type"] in ("domain", "sender_domain")]
        ips = [i["indicator"] for i in shared_indicators if i["type"] == "ip"]
        urls = [i["indicator"] for i in shared_indicators if i["type"] == "url"]

        if domains:
            recs.append(f"Implement perimeter DNS block / sinkhole for correlated domains: {', '.join(domains[:3])}.")
        if ips:
            recs.append(f"Add firewall drop rules for identified campaign MTA infrastructure: {', '.join(ips[:3])}.")
        if urls:
            recs.append("Quarantine incoming messages containing matching credential-harvesting URI paths.")

        recs.append("Initiate enterprise mailbox search for matching threat indicators to identify other targeted users.")
        if "credential" in threat_type.lower() or "phish" in threat_type.lower():
            recs.append("Enforce password resets and revoke active sessions for users who interacted with correlated links.")
        recs.append("Escalate identified campaign indicators to SIEM/EDR blocklists and SOC threat intelligence feed.")

        return recs

    def _generate_summary(
        self,
        campaign_name: str,
        email_count: int,
        shared_iocs: list[dict[str, Any]],
        reasons: list[str],
    ) -> str:
        ioc_types = defaultdict(int)
        for i in shared_iocs:
            ioc_types[i["type"]] += 1

        parts = []
        if ioc_types["url"]:
            parts.append(f"{ioc_types['url']} shared URL(s)")
        if ioc_types["domain"] or ioc_types["sender_domain"]:
            parts.append(f"{ioc_types['domain'] + ioc_types['sender_domain']} domain infrastructure node(s)")
        if ioc_types["ip"]:
            parts.append(f"{ioc_types['ip']} relay IP(s)")

        infra_desc = ", ".join(parts) if parts else "shared behavioral and sender patterns"
        reason_desc = "; ".join(reasons[:3]) if reasons else "correlated threat vectors"

        return (
            f"MailTrace AI identified a coordinated {campaign_name} spanning {email_count} correlated messages. "
            f"The campaign exhibits common threat vectors linking {infra_desc}. "
            f"Primary correlation indicators include: {reason_desc}. "
            f"Evidence indicates coordinated infrastructure sharing without attributing specific threat-actor identity."
        )

    def _normalize_url(self, url_str: str) -> str:
        try:
            cand = url_str.strip().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
            if "://" not in cand:
                cand = f"http://{cand}"
            parsed = urlsplit(cand)
            host = (parsed.hostname or "").lower()
            path = parsed.path.rstrip("/")
            if not host:
                return ""
            return f"{parsed.scheme}://{host}{path}"
        except Exception:
            return url_str.strip().lower()

    def _url_to_domain(self, url_str: str) -> str:
        try:
            cand = url_str.strip().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
            if "://" not in cand:
                cand = f"http://{cand}"
            return (urlsplit(cand).hostname or "").lower().strip("[]/")
        except Exception:
            return ""

    def _extract_email_addr(self, address_str: str) -> str:
        if not address_str:
            return ""
        match = re.search(r"[\w\.-]+@[\w\.-]+", address_str)
        return match.group(0).lower() if match else address_str.strip().lower()

    def _subject_similarity(self, subj_a: str, subj_b: str) -> float:
        if not subj_a or not subj_b:
            return 0.0
        # Tokenize and normalize words
        tokens_a = set(re.findall(r"\w+", subj_a.lower())) - {"re", "fwd", "urgent", "the", "a", "an", "is", "in", "to", "for", "of"}
        tokens_b = set(re.findall(r"\w+", subj_b.lower())) - {"re", "fwd", "urgent", "the", "a", "an", "is", "in", "to", "for", "of"}
        if not tokens_a or not tokens_b:
            return 1.0 if subj_a.strip().lower() == subj_b.strip().lower() else 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)
