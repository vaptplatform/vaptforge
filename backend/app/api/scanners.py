"""
SAST/DAST Scanner API — Dedicated endpoints for standalone scanning.
All three scanner modes (SAST-only, DAST-only, SAST+DAST combined) enforce
the domain whitelist so no one can bypass it via the standalone endpoints.
"""
import asyncio
import logging
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_analyst
from app.db.session import get_db
from app.models.models import DomainStatus, WhitelistedDomain

router = APIRouter()
logger = logging.getLogger("vapt.api.scanners")


# ── Request models ─────────────────────────────────────────────────────────────

class SASTCodeRequest(BaseModel):
    code: str
    filename: str = "code.py"


class SASTUrlRequest(BaseModel):
    target_url: str
    timeout: int = 30


class DASTScanRequest(BaseModel):
    target_url: str
    timeout: int = 60
    max_urls: int = 30


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _enforce_whitelist(target_url: str, org_id: str, db: AsyncSession) -> str:
    """Parse domain from URL and verify it is in the org's whitelist. Returns domain."""
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        if not domain:
            raise ValueError("no domain")
    except Exception:
        raise HTTPException(422, "Invalid target URL — cannot extract domain")

    result = await db.execute(
        select(WhitelistedDomain).where(
            WhitelistedDomain.org_id == org_id,
            WhitelistedDomain.domain == domain,
            WhitelistedDomain.status == DomainStatus.VERIFIED,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            403,
            f"Domain '{domain}' is not in your verified whitelist. "
            "Add and verify it in Settings → Domains before scanning.",
        )
    return domain


def _format_sast_finding(f) -> dict:
    return {
        "rule_id":     f.rule_id,
        "category":    f.category,
        "title":       f.title,
        "description": f.description,
        "severity":    f.severity,
        "file":        f.file_path,
        "line":        f.line_number,
        "snippet":     f.code_snippet,
        "remediation": f.remediation,
        "confidence":  f.confidence,
        "cwe":         f.cwe,
        "references":  f.references,
    }


def _format_dast_finding(f) -> dict:
    return {
        "test_id":     f.test_id,
        "category":    f.category,
        "title":       f.title,
        "description": f.description,
        "severity":    f.severity,
        "url":         f.url,
        "method":      f.method,
        "parameter":   f.parameter,
        "payload":     f.payload,
        "evidence":    f.evidence,
        "remediation": f.remediation,
        "confidence":  f.confidence,
        "cwe":         f.cwe,
        "references":  f.references,
    }


# ── SAST: paste code (no URL — whitelist N/A) ──────────────────────────────────

@router.post("/sast/code")
async def sast_scan_code(
    req: SASTCodeRequest,
    current_user=Depends(require_analyst),
):
    """Run SAST on a pasted code string. No URL → no whitelist check needed."""
    if not req.code.strip():
        raise HTTPException(400, "No code provided")
    if len(req.code) > 500_000:
        raise HTTPException(400, "Code too large (max 500 KB)")

    try:
        from app.scanner.sast_scanner import SASTScanner
        scanner  = SASTScanner()
        findings = scanner.scan_code_string(req.code, req.filename)
        summary  = scanner.get_summary()
        return {
            "success":        True,
            "scanner":        "SAST",
            "mode":           "code",
            "filename":       req.filename,
            "findings_count": len(findings),
            "summary":        summary,
            "findings":       [_format_sast_finding(f) for f in findings],
        }
    except Exception as e:
        logger.exception(f"SAST code scan error: {e}")
        raise HTTPException(500, f"SAST scan failed: {e}")


# ── SAST: URL mode ─────────────────────────────────────────────────────────────

@router.post("/sast/url")
async def sast_scan_url(
    req: SASTUrlRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Run SAST by fetching source/JS files from a URL. Enforces domain whitelist."""
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "target_url must start with http:// or https://")

    # ── Whitelist check ──
    await _enforce_whitelist(req.target_url, current_user.org_id, db)

    timeout = min(req.timeout, 30)

    try:
        import httpx
        from app.scanner.sast_scanner import SASTScanner
        from app.core.config import settings

        scanner = SASTScanner(timeout=timeout)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            headers={"User-Agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True,
            verify=False,
        ) as client:
            findings = await asyncio.wait_for(
                scanner.scan_url(req.target_url, client),
                timeout=timeout,
            )

        summary = scanner.get_summary()
        return {
            "success":        True,
            "scanner":        "SAST",
            "mode":           "url",
            "target_url":     req.target_url,
            "findings_count": len(findings),
            "summary":        summary,
            "findings":       [_format_sast_finding(f) for f in findings],
        }
    except asyncio.TimeoutError:
        raise HTTPException(408, f"SAST URL scan timed out after {timeout}s")
    except Exception as e:
        logger.exception(f"SAST URL scan error: {e}")
        raise HTTPException(500, f"SAST scan failed: {e}")


# ── DAST: live scan ────────────────────────────────────────────────────────────

@router.post("/dast/scan")
async def dast_scan(
    req: DASTScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Run DAST against a live URL. Enforces domain whitelist."""
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "target_url must start with http:// or https://")

    # ── Whitelist check ──
    await _enforce_whitelist(req.target_url, current_user.org_id, db)

    timeout = min(req.timeout, 60)

    try:
        import httpx
        from app.scanner.dast_scanner import DASTScanner
        from app.core.config import settings

        scanner = DASTScanner(timeout=timeout, max_urls=min(req.max_urls, 50))

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            headers={"User-Agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True,
            verify=False,
        ) as client:
            findings = await asyncio.wait_for(
                scanner.scan(req.target_url, client),
                timeout=timeout,
            )

        summary = scanner.get_summary()
        return {
            "success":        True,
            "scanner":        "DAST",
            "mode":           "url",
            "target_url":     req.target_url,
            "findings_count": len(findings),
            "summary":        summary,
            "findings":       [_format_dast_finding(f) for f in findings],
        }
    except asyncio.TimeoutError:
        raise HTTPException(408, f"DAST scan timed out after {timeout}s")
    except Exception as e:
        logger.exception(f"DAST scan error: {e}")
        raise HTTPException(500, f"DAST scan failed: {e}")


# ── SAST + DAST combined ───────────────────────────────────────────────────────

@router.post("/combined/scan")
async def combined_scan(
    req: DASTScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """
    Run SAST (source fetch) + DAST (live probe) concurrently.
    Each phase gets its own full timeout via asyncio.gather so a fast SAST
    failure doesn't steal time from DAST.
    Enforces domain whitelist.
    """
    if not req.target_url.startswith(("http://", "https://")):
        raise HTTPException(400, "target_url must start with http:// or https://")

    # ── Whitelist check ──
    await _enforce_whitelist(req.target_url, current_user.org_id, db)

    timeout      = min(req.timeout, 60)
    sast_timeout = min(timeout, 30)   # SAST gets up to 30 s of its own time
    dast_timeout = min(timeout, 55)   # DAST gets up to 55 s of its own time

    try:
        import httpx
        from app.scanner.sast_scanner import SASTScanner
        from app.scanner.dast_scanner import DASTScanner
        from app.core.config import settings

        sast_scanner = SASTScanner(timeout=sast_timeout)
        dast_scanner = DASTScanner(timeout=dast_timeout, max_urls=min(req.max_urls, 30))

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10),
            headers={"User-Agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True,
            verify=False,
        ) as client:

            async def _run_sast():
                return await asyncio.wait_for(
                    sast_scanner.scan_url(req.target_url, client),
                    timeout=sast_timeout,
                )

            async def _run_dast():
                return await asyncio.wait_for(
                    dast_scanner.scan(req.target_url, client),
                    timeout=dast_timeout,
                )

            # Run both independently — failures in one don't affect the other
            results = await asyncio.gather(_run_sast(), _run_dast(), return_exceptions=True)

        sast_findings, sast_error = ([], None)
        dast_findings, dast_error = ([], None)

        if isinstance(results[0], Exception):
            sast_error = str(results[0])
            logger.warning(f"SAST phase error in combined scan: {sast_error}")
        else:
            sast_findings = results[0]

        if isinstance(results[1], Exception):
            dast_error = str(results[1])
            logger.warning(f"DAST phase error in combined scan: {dast_error}")
        else:
            dast_findings = results[1]

        sast_summary = sast_scanner.get_summary()
        dast_summary = dast_scanner.get_summary()

        merged_counts = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            merged_counts[sev] = (
                sast_summary["counts"].get(sev, 0) +
                dast_summary["counts"].get(sev, 0)
            )

        total = len(sast_findings) + len(dast_findings)

        return {
            "success":        True,
            "scanner":        "SAST+DAST",
            "mode":           "combined",
            "target_url":     req.target_url,
            "findings_count": total,
            "summary": {
                "total":  total,
                "counts": merged_counts,
                "sast":   sast_summary,
                "dast":   dast_summary,
            },
            "sast": {
                "findings_count": len(sast_findings),
                "error":          sast_error,
                "findings":       [_format_sast_finding(f) for f in sast_findings],
            },
            "dast": {
                "findings_count": len(dast_findings),
                "error":          dast_error,
                "findings":       [_format_dast_finding(f) for f in dast_findings],
            },
        }

    except asyncio.TimeoutError:
        raise HTTPException(408, f"Combined scan timed out after {timeout}s")
    except Exception as e:
        logger.exception(f"Combined scan error: {e}")
        raise HTTPException(500, f"Combined scan failed: {e}")


# ── SAST rules reference ───────────────────────────────────────────────────────

@router.get("/sast/rules")
async def sast_rules(current_user=Depends(require_analyst)):
    from app.scanner.sast_scanner import SAST_RULES
    return {
        "rules": [
            {
                "id":          r["id"],
                "category":    r["category"],
                "title":       r["title"],
                "severity":    r["severity"],
                "cwe":         r.get("cwe", ""),
                "description": r["description"],
            }
            for r in SAST_RULES
        ]
    }
