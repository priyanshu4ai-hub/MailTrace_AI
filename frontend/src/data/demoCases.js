export const DEMO_CASES = {
  phishing: {
    id: 'INC-2026-08491',
    name: 'Spearphishing: Microsoft 365 MFA Token Harvester',
    threat_analysis: {
      classification: 'Phishing',
      confidence_score: 94,
      mitre_attack_mapping: 'T1566.002 — Spearphishing Link (Initial Access)',
      social_engineering_techniques: [
        'Urgency & Coercive Account Termination Trigger',
        'C-Suite / Microsoft Security Brand Impersonation',
        'Adversary-in-the-Middle (AiTM) MFA Harvesting Lure',
      ],
      suspicious_indicators: [
        'RFC 5321 (Return-Path) vs RFC 5322 (From) Domain Mismatch',
        'RFC 7208 SPF Verification Failure (Sender IP not in SPF record)',
        'RFC 7489 DMARC Alignment Failure (p=reject enforced)',
        'Newly Registered Lookalike Domain (login-targetcorp-auth.com — Age: 3 Days)',
        'Originating IP 198.51.100.22 associated with AS12389 (High-Risk Bulletproof ASN)',
      ],
      explanation: 'Inbound message exhibits high-confidence characteristics of a credential harvesting campaign. The sender displays "Target Corp IT Security" while routing from unauthenticated external infrastructure (198.51.100.22). Both SPF and DMARC alignment failed. Embedded call-to-action redirects to a newly registered typosquatted domain designed to capture Microsoft 365 session tokens.',
      recommended_action: 'Execute automated containment playbook PB-EMAIL-04: (1) Purge message across all tenant Exchange inboxes by Message-ID, (2) Block sender IP 198.51.100.22 and domain login-targetcorp-auth.com on perimeter firewall/EDR, (3) Force immediate password and MFA token revocation for recipient employee@target.com.',
    },
    email: {
      from: '"IT Security & Access Operations" <security-alerts@login-targetcorp-auth.com>',
      to: 'employee@target.com',
      subject: 'CRITICAL ACTION REQUIRED: Microsoft 365 MFA Re-Authentication Token Expired',
      date: 'Mon, 31 Aug 2026 14:22:18 +0000',
      message_id: '<20260831142218.88391.sec-ops@login-targetcorp-auth.com>',
      body: 'Dear Target Corp Employee,\n\nOur identity provider detected an expired multi-factor authentication (MFA) token associated with your corporate workstation (WS-US-99182).\n\nIn accordance with Target Corp Information Security Policy SEC-09, you are required to re-authenticate your Microsoft 365 Enterprise session within 60 minutes. Failure to complete verification will result in immediate Active Directory account lock and ticket escalation to your reporting manager.\n\nVerify MFA Credentials: https://login-targetcorp-auth.com/idp/auth/session?token=8f9a2b91c0\n\nTarget Corp Identity & Access Management (IAM)\nGlobal Security Operations Center',
      received_headers: [
        'from mail-relay.login-targetcorp-auth.com (unknown [198.51.100.22]) by mx.target.com with ESMTP id 88391 for <employee@target.com>; Mon, 31 Aug 2026 14:22:18 +0000',
        'from 10.0.4.12 (helo=attacker-vps.lan) by mail-relay.login-targetcorp-auth.com with SMTP id 44102; Mon, 31 Aug 2026 14:22:17 +0000',
      ],
      authentication_results: 'mx.target.com; spf=fail (domain of login-targetcorp-auth.com does not designate 198.51.100.22 as permitted sender) smtp.mailfrom=bounce@attacker-vps.net; dkim=none (message not signed); dmarc=fail (p=reject dis=quarantine) header.from=login-targetcorp-auth.com',
    },
    authentication: { spf: 'fail', dkim: 'none', dmarc: 'fail' },
    evidence_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    attack_graph: {
      nodes: [
        { id: 'employee@target.com', name: 'employee@target.com', type: 'recipient' },
        { id: 'security-alerts@login-targetcorp-auth.com', name: 'security-alerts@login-targetcorp-auth.com (Spoofed Sender)', type: 'sender' },
        { id: '198.51.100.22', name: '198.51.100.22 (Moscow, RU)', type: 'relay_ip', country: 'RU', city: 'Moscow', isp: 'Rostelecom AS12389', asn: 'AS12389' },
        { id: 'spf_fail', name: 'SPF: fail (RFC 7208)', type: 'authentication' },
        { id: 'dmarc_fail', name: 'DMARC: fail (p=reject)', type: 'authentication' },
        { id: 'phishing_verdict', name: 'Verdict: Malicious Phishing (94%)', type: 'threat_assessment' },
      ],
      links: [
        { source: 'security-alerts@login-targetcorp-auth.com', target: 'employee@target.com', relation: 'sent_to' },
        { source: '198.51.100.22', target: 'security-alerts@login-targetcorp-auth.com', relation: 'relayed_by' },
        { source: 'spf_fail', target: 'security-alerts@login-targetcorp-auth.com', relation: 'auth_audit' },
        { source: 'dmarc_fail', target: 'security-alerts@login-targetcorp-auth.com', relation: 'auth_audit' },
        { source: 'phishing_verdict', target: 'security-alerts@login-targetcorp-auth.com', relation: 'classified_by' },
      ],
    },
    geo_hops: [
      { ip: '198.51.100.22', city: 'Moscow', country: 'RU', isp: 'Rostelecom (AS12389)', asn: 'AS12389' },
    ],
  },

  bec: {
    id: 'INC-2026-08502',
    name: 'BEC: Executive Wire Fraud & M&A Impersonation',
    threat_analysis: {
      classification: 'BEC',
      confidence_score: 96,
      mitre_attack_mapping: 'T1566.002 — Spearphishing Link / BEC Fraud',
      social_engineering_techniques: [
        'Executive Display Name Impersonation (CEO)',
        'Confidentiality & Out-of-Band Channel Suppression',
        'High-Value Off-Cycle Wire Transfer Request',
      ],
      suspicious_indicators: [
        'C-Suite Impersonation: "Jonathan Vance (Chief Executive Officer)"',
        'Lookalike Typo Domain: "ce0-targetcorp.com" (0 for O)',
        'SPF Softfail: Originating IP 185.220.101.45 outside authorized envelope pool',
        'Urgent Financial Request: $142,500 escrow transfer bypassing ERP verification',
      ],
      explanation: 'Targeted Business Email Compromise (BEC) attack executing C-Suite impersonation. Attacker utilizes a visually deceptive lookalike domain (ce0-targetcorp.com) and coercive language requesting an immediate escrow transfer of $142,500 for confidential M&A proceedings.',
      recommended_action: 'Initiate finance department emergency alert. Halt any pending ACH/wire transactions matching invoice #AQ-9902. Verify transfer request out-of-band via trusted internal phone directory with executive office. Blacklist lookalike domain ce0-targetcorp.com.',
    },
    email: {
      from: '"Jonathan Vance (CEO)" <jvance@ce0-targetcorp.com>',
      to: 'finance-ops@target.com',
      subject: 'CONFIDENTIAL: Acquisition Escrow Wire Transfer (#AQ-9902)',
      date: 'Mon, 31 Aug 2026 15:45:10 +0000',
      message_id: '<bec-wire-88391@ce0-targetcorp.com>',
      body: 'Hi Sarah,\n\nI am currently in closed-door M&A negotiations with external counsel and cannot take direct phone calls. We need an urgent initial escrow deposit of $142,500 wired to our designated acquisition trust account before 5:00 PM EST today to secure the closing terms.\n\nPlease process invoice #AQ-9902 immediately to the routing instructions attached below. Keep this matter strictly confidential until our official press disclosure on Wednesday morning.\n\nBest regards,\nJonathan Vance\nChief Executive Officer\nTarget Corp Holdings',
      received_headers: [
        'from mail.ce0-targetcorp.com (vps-de-out.hetzner.net [185.220.101.45]) by mx.target.com with ESMTP id 88391 for <finance-ops@target.com>; Mon, 31 Aug 2026 15:45:10 +0000',
        'from 10.14.0.2 by mail.ce0-targetcorp.com with SMTP id 9912; Mon, 31 Aug 2026 15:45:09 +0000',
      ],
      authentication_results: 'mx.target.com; spf=softfail (domain of ce0-targetcorp.com does not designate 185.220.101.45 as permitted sender) smtp.mailfrom=bounce@ce0-targetcorp.com; dkim=fail; dmarc=fail (p=quarantine) header.from=ce0-targetcorp.com',
    },
    authentication: { spf: 'softfail', dkim: 'fail', dmarc: 'fail' },
    evidence_hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
    attack_graph: {
      nodes: [
        { id: 'finance-ops@target.com', name: 'finance-ops@target.com', type: 'recipient' },
        { id: 'jvance@ce0-targetcorp.com', name: 'jvance@ce0-targetcorp.com (CEO Spoof)', type: 'sender' },
        { id: '185.220.101.45', name: '185.220.101.45 (Frankfurt, DE)', type: 'relay_ip', country: 'DE', city: 'Frankfurt', isp: 'Hetzner Online', asn: 'AS24940' },
        { id: 'spf_softfail', name: 'SPF: softfail', type: 'authentication' },
        { id: 'bec_alert', name: 'Verdict: Critical BEC (96%)', type: 'threat_assessment' },
      ],
      links: [
        { source: 'jvance@ce0-targetcorp.com', target: 'finance-ops@target.com', relation: 'sent_to' },
        { source: '185.220.101.45', target: 'jvance@ce0-targetcorp.com', relation: 'relayed_by' },
        { source: 'spf_softfail', target: 'jvance@ce0-targetcorp.com', relation: 'auth_audit' },
        { source: 'bec_alert', target: 'jvance@ce0-targetcorp.com', relation: 'classified_by' },
      ],
    },
    geo_hops: [
      { ip: '185.220.101.45', city: 'Frankfurt', country: 'DE', isp: 'Hetzner Online (AS24940)', asn: 'AS24940' },
    ],
  },

  safe: {
    id: 'INC-2026-08310',
    name: 'Verified Clean: Internal Corporate Standup Notes',
    threat_analysis: {
      classification: 'Safe',
      confidence_score: 98,
      mitre_attack_mapping: 'None (Clean Message)',
      social_engineering_techniques: [],
      suspicious_indicators: [],
      explanation: 'All RFC email authentication checks passed with strict domain alignment. Cryptographic 2048-bit RSA DKIM signature is valid. Sender IP matches internal corporate MX gateway. Content analysis detected no coercive language, suspicious links, or unauthorized attachments.',
      recommended_action: 'No remediation required. Message is authentic, cryptographically verified, and cleared for standard inbox routing.',
    },
    email: {
      from: '"Alex Chen (Engineering Lead)" <alex.chen@target.com>',
      to: 'engineering-all@target.com',
      subject: 'Sprint 24 Retrospective Notes & Architecture Action Items',
      date: 'Mon, 31 Aug 2026 11:15:00 +0000',
      message_id: '<eng-standup-2026-08-31-001@target.com>',
      body: 'Hi Engineering Team,\n\nThank you for participating in this morning\'s Sprint 24 retrospective. The action items and Jira epics for the API gateway performance optimization have been updated on our internal Confluence space.\n\nPlease review your assigned tasks before tomorrow\'s sync. Great job on shipping the core deliverables ahead of schedule!\n\nBest regards,\nAlex Chen\nLead Systems Architect\nTarget Corp Engineering',
      received_headers: [
        'from mx-internal.target.com (mx-internal.target.com [203.0.113.50]) by mail-hub.target.com with ESMTP id 99201 for <engineering-all@target.com>; Mon, 31 Aug 2026 11:15:00 +0000',
      ],
      authentication_results: 'mx.target.com; spf=pass (target.com: 203.0.113.50 is authorized) smtp.mailfrom=alex.chen@target.com; dkim=pass (signature verified 2048-bit RSA) header.d=target.com; dmarc=pass (p=reject dis=none) header.from=target.com',
    },
    authentication: { spf: 'pass', dkim: 'pass', dmarc: 'pass' },
    evidence_hash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    attack_graph: {
      nodes: [
        { id: 'engineering-all@target.com', name: 'engineering-all@target.com', type: 'recipient' },
        { id: 'alex.chen@target.com', name: 'alex.chen@target.com (Verified Internal)', type: 'sender' },
        { id: '203.0.113.50', name: '203.0.113.50 (Corporate MX Gateway)', type: 'relay_ip', country: 'US', city: 'San Jose', isp: 'Target Internal ASN', asn: 'AS15169' },
        { id: 'auth_pass', name: 'SPF: pass | DKIM: pass | DMARC: pass', type: 'authentication' },
        { id: 'safe_verdict', name: 'Verdict: Clean Authentic (98%)', type: 'threat_assessment' },
      ],
      links: [
        { source: 'alex.chen@target.com', target: 'engineering-all@target.com', relation: 'sent_to' },
        { source: '203.0.113.50', target: 'alex.chen@target.com', relation: 'relayed_by' },
        { source: 'auth_pass', target: 'alex.chen@target.com', relation: 'validates' },
        { source: 'safe_verdict', target: 'alex.chen@target.com', relation: 'classified_by' },
      ],
    },
    geo_hops: [
      { ip: '203.0.113.50', city: 'San Jose', country: 'US', isp: 'Target Corp ASN (AS15169)', asn: 'AS15169' },
    ],
  },
}
