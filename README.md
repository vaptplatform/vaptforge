# VAPTForge Enterprise — Fixed & Ready

## What Was Fixed

### 🔴 Critical Bug Fixes
1. **`auth.py`** — `router` variable was accidentally overwritten by `logger` assignment (line 1 bug). Fixed.
2. **`report_service.py`** — PDF generation now always works using `reportlab` (no system dependencies like wkhtmltopdf required).
3. **`engine.py`** — Added 60-second scan timeout enforcement; scanner now cannot run indefinitely.
4. **`router.py`** — Added missing SAST/DAST scanner routes.
5. **Light mode CSS** — All text/input/button/table styles now have proper contrast in light mode.

### ✅ New Features Added
- **SAST Scanner** (`/scanners/sast/code`) — 10 detection rules covering: SQL injection sinks, XSS sinks, hardcoded secrets, command injection, path traversal, weak crypto, insecure deserialization, debug mode, JWT issues, SSRF
- **DAST Scanner** (`/scanners/dast/scan`) — Live web app scanning: security headers, sensitive paths, SQLi, XSS, SSTI, open redirect, cookie flags, HTTPS check
- **Scanners UI Page** — `/scanners` route with SAST code paste + DAST URL scan, results with expandable findings
- **Sidebar nav** — "SAST / DAST" link added under Tools group

### 📧 Email System
- SMTP configured: `smtp.gmail.com:587` with `vaptnotify@gmail.com`
- Set `SMTP_PASS` in `backend/.env` with your 16-char Gmail App Password
- Forgot password, scan completion, critical alerts, report sharing all work
- DEV MODE: if SMTP not configured, emails are logged to console (no fake success)

### 📄 PDF Reports
- `reportlab` added to `requirements.txt` — always available, no system deps
- PDF generation uses: WeasyPrint → pdfkit → reportlab (fallback chain)
- reportlab fallback creates structured PDFs with finding cards, severity colors, metadata

---

## Quick Start

### Backend
```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# (Optional) Better PDF quality:
pip install weasyprint

# Configure environment
cp .env.example .env
# Edit .env — set SMTP_PASS if you want real emails

# Start backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend runs at: http://localhost:8000  
API docs: http://localhost:8000/api/docs

### Frontend
```bash
cd frontend

# Install dependencies
npm install

# Start dev server
npm run dev
```

Frontend runs at: http://localhost:3000

---

## Scan Timeout
- Maximum: **60 seconds** (enforced in engine)
- DAST standalone scanner: configurable up to 60s
- Per-request HTTP timeout: 8 seconds

## Scanner Pages
- **Full OWASP Scan**: `/scans/new` → picks whitelisted domain → runs all 10 OWASP modules + SAST headers
- **SAST Scanner**: `/scanners` → paste code → instant analysis
- **DAST Scanner**: `/scanners` → enter URL → active probe

## API Endpoints
- `POST /api/v1/scanners/sast/code` — SAST scan of code string
- `POST /api/v1/scanners/dast/scan` — DAST scan of live URL
- `GET /api/v1/scanners/sast/rules` — list all SAST rules
- `GET /api/v1/reports/{scan_id}/pdf` — download PDF report
- `GET /api/v1/reports/{scan_id}/html` — download HTML report
- `POST /api/v1/auth/forgot-password` — trigger password reset email

## Environment Variables
| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | `vaptnotify@gmail.com` | Sender email |
| `SMTP_PASS` | *(set this)* | Gmail App Password |
| `FRONTEND_URL` | `http://localhost:3000` | For reset links |
| `REPORTS_DIR` | `./reports` | PDF/HTML output |
| `SCAN_REQUEST_TIMEOUT` | `8` | Per-request timeout (s) |
