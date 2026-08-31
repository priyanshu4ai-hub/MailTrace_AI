# Contributing to MailTrace AI

Thank you for your interest in contributing to **MailTrace AI**! We welcome contributions from developers, security researchers, DFIR analysts, and designers of all skill levels.

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all community members with respect and professionalism.

---

## How Can You Contribute?

You can contribute in many ways:
- **Reporting Bugs:** Help us identify issues with email parsing, UI responsiveness, or threat scoring.
- **Suggesting Features:** Propose new detection rules, email protocol checks, or visualization tools.
- **Adding Test Samples:** Submit sanitized `.eml` samples representing emerging phishing techniques (AiTM, QR phishing, spoofing).
- **Submitting Pull Requests:** Fix open issues, improve documentation, or implement new capabilities.

---

## Getting Started Locally

### 1. Fork & Clone
```bash
git clone https://github.com/<your-username>/MailTrace_AI.git
cd MailTrace_AI
git remote add upstream https://github.com/subhasankarpanda24/MailTrace_AI.git
```

### 2. Backend Setup (FastAPI)
```bash
cd backend
python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Run backend tests:
```bash
pytest
```

### 3. Frontend Setup (React 19 + Vite)
```bash
cd ../frontend
npm install
npm run dev
```
Validate build and linting:
```bash
npm run build
```

---

## Development Workflow & Guidelines

1. **Create a Feature Branch:**
   ```bash
   git checkout -b feat/your-feature-name
   # or
   git checkout -b fix/issue-description
   ```

2. **Commit Convention:**
   We follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New features or user capabilities
   - `fix:` Bug fixes or calculation corrections
   - `docs:` Documentation updates
   - `refactor:` Code improvements without behavioral changes
   - `test:` Adding or updating tests
   - `ci:` Pipeline and build configuration changes

3. **Code Style & Standards:**
   - **Backend (Python):** PEP 8 compliance, explicit type hints, Pydantic models for validation, and proper error handling.
   - **Frontend (React):** Clean functional components, CSS variable theme integration (supporting both Dark and Light modes), accessible semantic markup, and responsive layouts.

4. **Testing Your Changes:**
   Ensure both the backend API and frontend workstation build cleanly without errors before submitting.

---

## Submitting a Pull Request (PR)

1. Push your branch to your fork:
   ```bash
   git push origin feat/your-feature-name
   ```
2. Open a Pull Request on the main repository targeting the `main` branch.
3. Fill in the provided Pull Request template with:
   - A clear description of the problem solved or feature added.
   - Screenshots/GIFs for UI changes.
   - Steps taken to test the changes.

---

## Security Vulnerabilities

If you discover a security vulnerability, please review our [Security Policy](SECURITY.md) to report it responsibly.

Thank you for helping make MailTrace AI the premier open-source email forensics platform!
