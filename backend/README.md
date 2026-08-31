# MAILTRACE local phishing detector

The API now includes an offline, explainable phishing-risk model at
`POST /api/v1/phishing/analyze`. It does **not** fetch, resolve, or open supplied
URLs. That makes results deterministic and prevents the scanner from becoming an
SSRF or attacker-tracking endpoint.

It combines URL normalization (including `hxxp` and `[.]` defanging), host and
IDN/lookalike checks, brand impersonation, redirect and short-link analysis,
sender and Reply-To mismatches, SPF/DKIM/DMARC failures, and credential, urgency,
payment, and attachment lures. Independent signal groups are fused with a bounded
noisy-OR score, then returned with the exact indicators that contributed.

## Run

```powershell
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Scan a URL or message

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/v1/phishing/analyze `
  -ContentType 'application/json' `
  -Body '{"url":"hxxps://paypal-security[.]top/verify","text":"Urgent: confirm your password now"}'
```

The existing `POST /api/v1/investigate` endpoint automatically applies the same
detector to parsed email text, HTML `href` targets, sender metadata, and mail
authentication results. The result appears in
`threat_analysis.deterministic_assessment`.

## Deployment privacy defaults

The detector is fully local. Browser access is restricted by default to the Vite
development origins, and both external services are disabled by default:

- `MAILTRACE_ENABLE_LLM_ENRICHMENT=true` sends limited email evidence to Groq.
- `MAILTRACE_ENABLE_GEO_OSINT=true` looks up public SMTP relay IPs through ip-api.
- `MAILTRACE_CORS_ORIGINS=https://app.example.com` sets the permitted browser origin.

Copy `.env.example` to `.env` and set only the services approved for your deployment.

## Verify

```powershell
cd backend
python -m unittest discover -s tests -v
```

Scores are evidence-driven triage, not a guarantee of safety. For a production
deployment, add reputation feeds, sandboxed browser detonation, and a calibrated
supervised model trained on the organization’s reviewed samples.
