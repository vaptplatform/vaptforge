"""
Scans API — Create, list, manage vulnerability scans
Enforces whitelist-based authorization before any scan starts.
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import require_analyst, require_viewer
from app.db.session import get_db
from app.core.config import settings
from app.models.models import (
    AuditLog, DomainStatus, Scan, ScanProfile, ScanStatus, WhitelistedDomain,
)

logger = logging.getLogger("vapt.api.scans")
router = APIRouter()


class CreateScanRequest(BaseModel):
    target_url: str
    profile: ScanProfile = ScanProfile.FULL_OWASP
    enabled_modules: dict = {}
    scan_options: dict = {}


def _scan_to_dict(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "target_domain": scan.target_domain,
        "profile": scan.profile.value if hasattr(scan.profile, "value") else str(scan.profile),
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
        "progress": scan.progress,
        "risk_score": scan.risk_score,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "info_count": scan.info_count,
        "urls_crawled": scan.urls_crawled,
        "total_requests": scan.total_requests,
        "created_at": scan.created_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
    }


async def _run_scan_background(scan_id: str) -> None:
    """Background task: run scanner engine + send completion notifications."""
    from app.db.session import AsyncSessionLocal
    from app.scanner.engine import ScannerEngine
    from app.services.email_service import email_service
    from app.models.models import User, UserRole, Organization, Finding, Severity

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error(f"Scan {scan_id} not found for background execution")
            return

        engine = ScannerEngine(scan, db)
        try:
            await engine.run()
        except Exception as e:
            logger.exception(f"Background scan {scan_id} failed: {e}")
            return

        # Reload scan after engine run
        await db.refresh(scan)

        if scan.status != ScanStatus.COMPLETED:
            return

        # Fetch org admins for email notification
        admin_result = await db.execute(
            select(User).where(
                User.org_id == scan.org_id,
                User.role == UserRole.ADMIN,
                User.is_active == True,
            )
        )
        admins = admin_result.scalars().all()

        org_result = await db.execute(
            select(Organization).where(Organization.id == scan.org_id)
        )
        org = org_result.scalar_one_or_none()
        org_name = org.name if org else "Your Organization"

        if not admins:
            return

        # Calculate duration
        duration = 0
        if scan.started_at and scan.completed_at:
            started = scan.started_at.replace(tzinfo=timezone.utc) if scan.started_at.tzinfo is None else scan.started_at
            completed = scan.completed_at.replace(tzinfo=timezone.utc) if scan.completed_at.tzinfo is None else scan.completed_at
            duration = max(1, int((completed - started).total_seconds() / 60))

        # Send completion email
        try:
            await email_service.send_scan_completed(
                recipients=[u.email for u in admins],
                org_name=org_name,
                target_url=scan.target_url,
                scan_id=scan.id,
                critical=scan.critical_count,
                high=scan.high_count,
                medium=scan.medium_count,
                low=scan.low_count,
                risk_score=scan.risk_score or 0,
                duration_min=duration,
                dashboard_url=f"{settings.FRONTEND_URL}/scans/{scan.id}",
            )
        except Exception as e:
            logger.warning(f"Failed to send completion email: {e}")

        # Send critical alert if applicable
        if scan.critical_count > 0:
            try:
                crit_result = await db.execute(
                    select(Finding).where(
                        Finding.scan_id == scan.id,
                        Finding.severity == Severity.CRITICAL,
                    ).limit(1)
                )
                first_crit = crit_result.scalar_one_or_none()
                if first_crit:
                    await email_service.send_critical_alert(
                        recipients=[u.email for u in admins],
                        org_name=org_name,
                        target_url=scan.target_url,
                        vuln_title=first_crit.title,
                        owasp_category=first_crit.owasp_category,
                        severity="critical",
                        affected_endpoint=first_crit.affected_url,
                        description=first_crit.description,
                        dashboard_url=f"{settings.FRONTEND_URL}/scans/{scan.id}",
                    )
            except Exception as e:
                logger.warning(f"Failed to send critical alert: {e}")


@router.post("", status_code=201)
async def create_scan(
    data: CreateScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Create and queue a new scan. Enforces domain whitelist."""
    try:
        parsed = urlparse(data.target_url)
        domain = parsed.netloc or parsed.path
        if not domain:
            raise ValueError("No domain found")
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid target URL")

    # Whitelist enforcement
    result = await db.execute(
        select(WhitelistedDomain).where(
            WhitelistedDomain.org_id == current_user.org_id,
            WhitelistedDomain.domain == domain,
            WhitelistedDomain.status == DomainStatus.VERIFIED,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=403,
            detail=(
                f"Domain '{domain}' is not in your verified whitelist. "
                "Add and verify the domain in Settings before scanning."
            ),
        )

    # Concurrent scan limit
    running_result = await db.execute(
        select(Scan).where(
            Scan.org_id == current_user.org_id,
            Scan.status.in_([ScanStatus.RUNNING, ScanStatus.QUEUED]),
        )
    )
    if len(running_result.scalars().all()) >= 3:
        raise HTTPException(status_code=429, detail="Maximum concurrent scans (3) reached")

    scan = Scan(
        org_id=current_user.org_id,
        initiated_by=current_user.id,
        target_url=data.target_url,
        target_domain=domain,
        profile=data.profile,
        enabled_modules=data.enabled_modules,
        scan_options=data.scan_options,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.add(AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="SCAN_START",
        resource_type="scan",
        resource_id=scan.id,
        details={"target": data.target_url, "profile": str(data.profile)},
    ))
    await db.commit()

    background_tasks.add_task(_run_scan_background, scan.id)
    logger.info(f"Scan {scan.id} queued for {data.target_url}")
    return _scan_to_dict(scan)


@router.get("")
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    q = (
        select(Scan)
        .where(Scan.org_id == current_user.org_id)
        .order_by(desc(Scan.created_at))
    )
    if status:
        q = q.where(Scan.status == status)
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    scans = result.scalars().all()
    return {"scans": [_scan_to_dict(s) for s in scans], "page": page, "per_page": per_page}


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_to_dict(scan)


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        raise HTTPException(status_code=400, detail="Scan is not running")

    scan.status = ScanStatus.CANCELLED
    db.add(AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="SCAN_CANCEL",
        resource_type="scan",
        resource_id=scan_id,
        details={},
    ))
    await db.commit()
    return {"message": "Scan cancelled"}


@router.delete("/{scan_id}", status_code=200)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status in (ScanStatus.RUNNING, ScanStatus.QUEUED):
        raise HTTPException(status_code=400, detail="Cannot delete a running or queued scan. Cancel it first.")

    await db.delete(scan)
    db.add(AuditLog(
        org_id=current_user.org_id,
        user_id=current_user.id,
        action="SCAN_DELETE",
        resource_type="scan",
        resource_id=scan_id,
        details={"target": scan.target_url},
    ))
    await db.commit()
    return {"message": "Scan deleted"}


@router.get("/{scan_id}/traffic-summary")
async def get_traffic_summary(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == current_user.org_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        "urls_crawled": scan.urls_crawled,
        "total_requests": scan.total_requests,
        "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
    }