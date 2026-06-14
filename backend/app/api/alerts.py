"""
Alerts & Email API — Send reports, trigger alerts, webhooks
"""
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import require_analyst, require_viewer
from app.db.session import get_db
from app.models.models import AuditLog, Finding, Organization, Scan, Severity
from app.services.email_service import email_service
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger("vapt.api.alerts")


class SendReportRequest(BaseModel):
    scan_id: str
    recipients: List[str]
    message: Optional[str] = ""
    include_pdf: bool = True


class SendAlertRequest(BaseModel):
    scan_id: str
    recipients: List[str]
    message: Optional[str] = ""
    finding_id: Optional[str] = None


class WebhookTestRequest(BaseModel):
    webhook_url: str


async def _fetch_scan_and_org(scan_id: str, org_id: str, db: AsyncSession):
    """Shared helper to fetch scan + org."""
    r = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
    )
    scan = r.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    org_r = await db.execute(
        select(Organization).where(Organization.id == org_id)
    )
    org = org_r.scalar_one_or_none()
    return scan, org.name if org else "Your Organization"


@router.post("/send-report")
async def send_report_email(
    data: SendReportRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Send a security report to recipients via email."""
    scan, org_name = await _fetch_scan_and_org(data.scan_id, current_user.org_id, db)
    report_url = f"{settings.FRONTEND_URL}/scans/{scan.id}"

    # Build PDF attachment if requested
    pdf_bytes = None
    if data.include_pdf:
        try:
            from app.api.reports import _get_scan_with_findings
            from app.services.report_service import report_generator
            scan_data, findings = await _get_scan_with_findings(
                scan.id, current_user.org_id, db
            )
            html = report_generator.generate_html(scan_data, findings)
            pdf_path = report_generator.generate_pdf(html, scan.id)
            if pdf_path:
                with open(pdf_path, "rb") as f:
                    pdf_bytes = f.read()
        except Exception as e:
            logger.warning(f"PDF generation for email failed: {e}")

    result = await email_service.send_report_share(
        recipients=[str(r) for r in data.recipients],
        org_name=org_name,
        target_url=scan.target_url,
        sender_name=current_user.full_name,
        message=data.message or "",
        report_url=report_url,
        pdf_attachment=pdf_bytes,
        pdf_filename=f"security_report_{scan.id[:8]}.pdf",
    )

    db.add(AuditLog(
        org_id=current_user.org_id, user_id=current_user.id,
        action="REPORT_SHARED", resource_type="scan", resource_id=scan.id,
        details={"recipients": [str(r) for r in data.recipients], "success": result["success"]},
    ))
    await db.commit()
    return result


@router.post("/send-alert")
async def send_manual_alert(
    data: SendAlertRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_analyst),
):
    """Manually trigger a vulnerability alert email."""
    scan, org_name = await _fetch_scan_and_org(data.scan_id, current_user.org_id, db)

    vuln_title  = "Security Alert"
    owasp_cat   = "Multiple"
    sev         = "high"
    endpoint    = scan.target_url
    description = data.message or f"Manual security alert for scan of {scan.target_url}"

    if data.finding_id:
        fr = await db.execute(
            select(Finding).where(
                Finding.id == data.finding_id,
                Finding.org_id == current_user.org_id,
            )
        )
        finding = fr.scalar_one_or_none()
        if finding:
            vuln_title  = finding.title
            owasp_cat   = finding.owasp_category
            sev         = str(finding.severity)
            endpoint    = finding.affected_url
            description = finding.description

    result = await email_service.send_critical_alert(
        recipients=[str(r) for r in data.recipients],
        org_name=org_name,
        target_url=scan.target_url,
        vuln_title=vuln_title,
        owasp_category=owasp_cat,
        severity=sev,
        affected_endpoint=endpoint,
        description=description,
        dashboard_url=f"{settings.FRONTEND_URL}/scans/{scan.id}",
    )

    db.add(AuditLog(
        org_id=current_user.org_id, user_id=current_user.id,
        action="ALERT_SENT",
        details={"recipients": [str(r) for r in data.recipients], "scan_id": data.scan_id},
    ))
    await db.commit()
    return result


@router.post("/test-webhook")
async def test_webhook(
    data: WebhookTestRequest,
    current_user=Depends(require_analyst),
):
    payload = {
        "event": "webhook_test",
        "platform": "VAPTForge Enterprise",
        "org": current_user.org_id,
        "message": "Webhook test from VAPTForge",
    }
    success = await email_service.send_webhook(data.webhook_url, payload)
    return {"success": success, "webhook_url": data.webhook_url}


@router.get("/scan/{scan_id}/notification-status")
async def get_notification_history(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_viewer),
):
    r = await db.execute(
        select(AuditLog).where(
            AuditLog.org_id == current_user.org_id,
            AuditLog.resource_id == scan_id,
            AuditLog.action.in_(["REPORT_SHARED", "ALERT_SENT", "REPORT_GENERATED"]),
        ).order_by(desc(AuditLog.created_at))
    )
    logs = r.scalars().all()
    return {
        "notifications": [
            {"action": l.action, "details": l.details, "timestamp": l.created_at}
            for l in logs
        ]
    }
