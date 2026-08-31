# MailTrace AI — Email Threat Intelligence & Forensic Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0+-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Tailwind CSS](https://img.shields.io/badge/TailwindCSS-3.4+-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

**MailTrace AI (SIH26106)** is an open-source, enterprise-grade Digital Forensics & Incident Response (DFIR) platform for automated email threat triage, header forensics, and infrastructure correlation.

---

## Key Features

- **Interactive Correlated Attack Graph:** Visual topology mapping sender identities, envelope Return-Paths, intermediate relay IPs, authentication results, and AI threat classifications.
- **Deep RFC 5322 & RFC 5321 Forensic Engine:** Detects envelope spoofing and display name impersonation by comparing `5321.MailFrom` against `5322.From`.
- **Protocol Authentication Audit:** Comprehensive verification of SPF (RFC 7208), DKIM cryptographic RSA signatures (RFC 6376), and DMARC alignment/enforcement policies (RFC 7489).
- **Automated Threat Intelligence & IOC Workbench:** Extracts and defangs domain lookalikes, suspect relay IPs, URLs, hashes, and aligns observables with the MITRE ATT&CK® Enterprise Matrix.
- **Microsecond Timeline Trace:** End-to-end execution logging across ingestion, MIME decoding, authentication audits, GeoIP OSINT, and LLM semantic triage.
- **DFIR Incident Reporting:** Instant generation of executive summaries, printable PDF reports, Markdown documentation, and JSON audit payloads.
- **Dark & Light Mode Workstation:** Seamless theme switching with high-contrast, accessible DFIR layouts.
- **Built-in Scenario Triage:** One-click preloaded test cases (M365 MFA Spearphishing, C-Suite BEC Wire Fraud, and Legitimate Enterprise Mail) plus live `.eml` upload support.

---

## Architecture Overview

```
MailTrace AI
├── backend/                  # FastAPI Python Backend
│   ├── app/
│   │   ├── api/routes.py     # /api/v1/investigate endpoint
│   │   ├── models/schemas.py # Pydantic v2 data models
│   │   └── services/         # Parser, AuthVerifier, GeoTracker, AI Engine
│   └── samples/              # Real-world test .eml files
└── frontend/                 # React 19 + Vite + Tailwind CSS
    ├── src/
    │   ├── components/       # InvestigationView & DFIR tab modules
    │   ├── data/demoCases.js # Structured forensic case presets
    │   └── index.css         # Dynamic SOC theme variables & print styles
```

---

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ & npm

### 1. Backend Setup
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API Documentation will be available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Workstation UI will be running at `http://127.0.0.1:5173`.

---

## Testing Sample Emails

You can test with any standard `.eml` or `.txt` email file via the UI, or run against backend samples via cURL:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/investigate" \
  -F "file=@backend/samples/phishing-demo.eml"
```

---

## Contributing

We love contributions! Whether you're fixing a bug, adding new threat detection heuristics, or improving UI accessibility, please check out our [Contributing Guidelines](CONTRIBUTING.md) to get started.

- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## SIH 2026 Project Information
- **Problem Statement ID:** SIH26106
- **Domain:** Cybersecurity / Threat Intelligence / Digital Forensics (DFIR)
