"""
Reports API — Generate, download, regenerate reports in HTML / JSON / PDF
"""
# ── Windows GTK / WeasyPrint fix — MUST be before any weasyprint import ──────
import os
import sys

if sys.platform == "win32":
    _GTK_PATHS = [
        r"C:\Program Files\GTK3-Runtime Win64\bin",
        r"C:\Program Files (x86)\GTK3-Runtime Win64\bin",
        r"C:\GTK\bin",
    ]
    for _p in _GTK_PATHS:
        if os.path.exists(_p):
            os.add_dll_directory(_p)
            os.environ["PATH"] = _p + ";" + os.environ.get("PATH", "")
            break
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import asyncio
import threading
from functools import partial
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_analyst, require_viewer
from app.db.session import get_db
from app.models.models import AuditLog, Finding, Organization, Scan
from app.services.report_service import report_generator
from app.core.config import settings
from app.services.email_service import email_service

router = APIRouter()
logger = logging.getLogger("vapt.api.reports")

# Silence noisy WeasyPrint CSS warnings — they are cosmetic only
logging.getLogger("weasyprint").setLevel(logging.ERROR)
logging.getLogger("weasyprint.progress").setLevel(logging.ERROR)

# ── In-memory PDF job tracker ─────────────────────────────────────────────────
# Maps scan_id -> {"status": "pending"|"done"|"error", "path": str|None, "error": str|None}
_pdf_jobs: dict = {}
_pdf_jobs_lock = threading.Lock()


# ── Shared helper ─────────────────────────────────────────────────────────────

async def _build_scan_data(scan_id: str, org_id: str, db: AsyncSession) -> tuple:
    r = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
    )
    scan = r.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    fr = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = fr.scalars().all()

    org_r = await db.execute(select(Organization).where(Organization.id == org_id))
    org   = org_r.scalar_one_or_none()

    scan_data = {
        "id":             scan.id,
        "target_url":     scan.target_url,
        "profile":        str(scan.profile.value if hasattr(scan.profile, "value") else scan.profile),
        "status":         str(scan.status.value  if hasattr(scan.status,  "value") else scan.status),
        "started_at":     scan.started_at,
        "completed_at":   scan.completed_at,
        "urls_crawled":   scan.urls_crawled,
        "total_requests": scan.total_requests,
        "risk_score":     scan.risk_score or 0,
        "org_id":         org_id,
        "org_name":       org.name if org else "Unknown Org",
        "critical_count": scan.critical_count,
        "high_count":     scan.high_count,
        "medium_count":   scan.medium_count,
        "low_count":      scan.low_count,
    }
    return scan_data, findings


async def _log_report(db, org_id, user_id, scan_id, fmt):
    db.add(AuditLog(
        org_id=org_id, user_id=user_id,
        action="REPORT_GENERATED",
        resource_type="scan", resource_id=scan_id,
        details={"format": fmt},
    ))
    await db.commit()


def _run_pdf_job(scan_id: str, html: str):
    """Runs in a background thread. Updates _pdf_jobs when done."""
    try:
        path = report_generator.generate_pdf(html, scan_id)
        with _pdf_jobs_lock:
            if path and os.path.exists(path):
                _pdf_jobs[scan_id] = {"status": "done", "path": path, "error": None}
            else:
                _pdf_jobs[scan_id] = {"status": "error", "path": None, "error": "PDF generation returned no file"}
    except Exception as e:
        with _pdf_jobs_lock:
            _pdf_jobs[scan_id] = {"status": "error", "path": None, "error": str(e)}


# ── JSON ──────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}/json")
async def download_json(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_viewer),
):
    scan_data, findings = await _build_scan_data(scan_id, current_user.org_id, db)

    loop = asyncio.get_event_loop()
    report = await loop.run_in_executor(
        None, partial(report_generator.generate_json, scan_data, findings)
    )

    await _log_report(db, current_user.org_id, current_user.id, scan_id, "json")

    filename = f"vapt_report_{scan_id[:8]}.json"
    body = json.dumps(report, indent=2, default=str).encode("utf-8")
    return Response(
        content=body,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(body)),
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


# ── HTML ──────────────────────────────────────────────────────────────────────

@router.get("/{scan_id}/html")
async def download_html(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_viewer),
):
    scan_data, findings = await _build_scan_data(scan_id, current_user.org_id, db)

    loop = asyncio.get_event_loop()
    html = await loop.run_in_executor(
        None, partial(report_generator.generate_html, scan_data, findings)
    )
    path = report_generator.save_html(html, scan_id)

    await _log_report(db, current_user.org_id, current_user.id, scan_id, "html")

    filename = f"vapt_report_{scan_id[:8]}.html"
    return FileResponse(
        path,
        media_type="text/html",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


# ── PDF — async two-step: kick off → poll → download ─────────────────────────

@router.post("/{scan_id}/pdf/start")
async def start_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_viewer),
):
    """
    Kick off PDF generation in a background thread.
    Returns immediately with {"status": "pending"}.
    Poll GET /pdf/status until "done", then call GET /pdf/download.
    """
    scan_data, findings = await _build_scan_data(scan_id, current_user.org_id, db)

    with _pdf_jobs_lock:
        existing = _pdf_jobs.get(scan_id)
        # If already running or freshly done, don't restart
        if existing and existing["status"] in ("pending", "done"):
            return {"status": existing["status"], "scan_id": scan_id}
        _pdf_jobs[scan_id] = {"status": "pending", "path": None, "error": None}

    loop = asyncio.get_event_loop()
    html = await loop.run_in_executor(
        None, partial(report_generator.generate_html, scan_data, findings)
    )

    # Fire PDF generation in a daemon thread — does NOT block the response
    t = threading.Thread(target=_run_pdf_job, args=(scan_id, html), daemon=True)
    t.start()

    return {"status": "pending", "scan_id": scan_id}


@router.get("/{scan_id}/pdf/status")
async def pdf_status(
    scan_id: str,
    current_user = Depends(require_viewer),
):
    """Poll this endpoint. Returns {"status": "pending"|"done"|"error", "error": ...}"""
    with _pdf_jobs_lock:
        job = _pdf_jobs.get(scan_id)
    if not job:
        return {"status": "not_started"}
    return {"status": job["status"], "error": job.get("error")}


@router.get("/{scan_id}/pdf/download")
async def download_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_viewer),
):
    """Call only after /pdf/status returns {"status": "done"}."""
    with _pdf_jobs_lock:
        job = _pdf_jobs.get(scan_id)

    if not job:
        raise HTTPException(404, "No PDF job found — call POST /pdf/start first")
    if job["status"] == "pending":
        raise HTTPException(202, "PDF is still generating — poll /pdf/status")
    if job["status"] == "error":
        raise HTTPException(500, f"PDF generation failed: {job['error']}")

    path = job["path"]
    if not path or not os.path.exists(path):
        raise HTTPException(500, "PDF file missing")

    await _log_report(db, current_user.org_id, current_user.id, scan_id, "pdf")

    # Clear the job so next request regenerates fresh
    with _pdf_jobs_lock:
        _pdf_jobs.pop(scan_id, None)

    filename = f"vapt_report_{scan_id[:8]}.pdf"
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


# ── Legacy single-step PDF (kept for backwards compat, uses thread) ───────────

@router.get("/{scan_id}/pdf")
async def download_pdf_legacy(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_viewer),
):
    """
    Single-step PDF. Works but takes 30-90s — browser may show a spinner.
    Prefer the /pdf/start → /pdf/status → /pdf/download flow for better UX.
    """
    scan_data, findings = await _build_scan_data(scan_id, current_user.org_id, db)

    loop = asyncio.get_event_loop()
    html = await loop.run_in_executor(
        None, partial(report_generator.generate_html, scan_data, findings)
    )
    path = await loop.run_in_executor(
        None, partial(report_generator.generate_pdf, html, scan_id)
    )

    if not path or not os.path.exists(path):
        raise HTTPException(500, "PDF generation failed — check server logs")

    await _log_report(db, current_user.org_id, current_user.id, scan_id, "pdf")

    filename = f"vapt_report_{scan_id[:8]}.pdf"
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


# ── Regenerate ────────────────────────────────────────────────────────────────

class RegenerateRequest(BaseModel):
    send_email:  bool = False
    recipients:  Optional[List[str]] = None
    include_pdf: bool = True


@router.post("/{scan_id}/regenerate")
async def regenerate_report(
    scan_id: str,
    data:         RegenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user     = Depends(require_analyst),
):
    scan_data, findings = await _build_scan_data(scan_id, current_user.org_id, db)

    loop = asyncio.get_event_loop()
    html = await loop.run_in_executor(
        None, partial(report_generator.generate_html, scan_data, findings)
    )
    html_path = report_generator.save_html(html, scan_id)

    pdf_path = await loop.run_in_executor(
        None, partial(report_generator.generate_pdf, html, scan_id)
    )

    result = {
        "success":        True,
        "scan_id":        scan_id,
        "html_path":      html_path,
        "pdf_path":       pdf_path,
        "findings_count": len(findings),
        "email_sent":     False,
        "email_result":   None,
    }

    db.add(AuditLog(
        org_id=current_user.org_id, user_id=current_user.id,
        action="REPORT_REGENERATED",
        resource_type="scan", resource_id=scan_id,
        details={"findings": len(findings), "send_email": data.send_email},
    ))
    await db.commit()

    if data.send_email and data.recipients:
        pdf_bytes = None
        if data.include_pdf and pdf_path and pdf_path.endswith(".pdf"):
            try:
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
            except Exception:
                pass

        email_res = await email_service.send_report_share(
            recipients=data.recipients,
            org_name=scan_data["org_name"],
            target_url=scan_data["target_url"],
            sender_name=current_user.full_name,
            message="Please find your re-generated security assessment report.",
            report_url=f"{settings.FRONTEND_URL}/scans/{scan_id}",
            pdf_attachment=pdf_bytes,
            pdf_filename=f"vapt_report_{scan_id[:8]}.pdf",
        )
        result["email_sent"]   = email_res.get("success", False)
        result["email_result"] = email_res

    return result

# ── Scanner Page Email Report ──────────────────────────────────────────────────
class ScannerEmailRequest(BaseModel):
    recipients:   list[str]
    html_content: str
    subject:      str = "VAPTForge Security Scanner Report"
    include_pdf:  bool = False


@router.post("/send-scanner-report")
async def send_scanner_report(
    data: ScannerEmailRequest,
    current_user=Depends(require_analyst),
):
    """Send SAST/DAST scanner page report HTML directly via email."""
    if not data.recipients:
        raise HTTPException(status_code=400, detail="At least one recipient required")

    emails = [str(r).strip() for r in data.recipients if str(r).strip()]
    if not emails:
        raise HTTPException(status_code=400, detail="No valid recipient emails")

    try:
        result = await email_service.send_report_share(
            recipients=emails,
            org_name="VAPTForge Enterprise",
            target_url="SAST/DAST Scanner",
            sender_name=current_user.full_name,
            message=f"Please find your {data.subject} attached.",
            report_url=f"{settings.FRONTEND_URL}/scanners",
            pdf_attachment=None,
        )
        logger.info(f"Scanner report emailed to {emails} by {current_user.email}")
        return result
    except Exception as e:
        logger.error(f"Scanner email failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Email failed: {str(e)}")
