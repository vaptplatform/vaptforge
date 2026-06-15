"""
VAPTForge Email Service — SendGrid HTTP API (Render-compatible)
"""
import asyncio
import logging
import re
import os
import base64
from datetime import datetime, timezone
from typing import List, Optional
from app.core.config import settings

logger = logging.getLogger("vapt.email")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

SENDER_NAME  = "VAPTForge Security"
_FALLBACK_EMAIL = "vaptnotify@gmail.com"

def _get_sender_email() -> str:
    from app.core.config import settings
    return str(settings.SMTP_USER).strip() if settings.SMTP_USER else _FALLBACK_EMAIL


def _base_html(org: str, title: str, content: str,
               cta_url: str = "", cta_label: str = "View Report") -> str:
    cta = f"""<div style="text-align:center;margin:32px 0;">
      <a href="{cta_url}" style="background:#1E40AF;color:white;padding:13px 32px;
         border-radius:8px;text-decoration:none;font-weight:700;font-size:14px;
         display:inline-block;">{cta_label} →</a></div>""" if cta_url else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>{title}</title></head>
<body style="margin:0;padding:0;background:#F1F5F9;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F1F5F9;padding:40px 16px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0"
  style="background:#FFFFFF;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
  <tr><td style="background:linear-gradient(135deg,#0F172A,#1E3A5F);padding:28px 36px;">
    <span style="font-size:20px;font-weight:800;color:white;">
      ■ VAPT<span style="color:#60A5FA;">Forge</span>
    </span>
    <span style="float:right;font-size:11px;color:#64748B;">{org}</span>
  </td></tr>
  <tr><td style="padding:36px;">
    <h2 style="color:#0F172A;font-size:22px;font-weight:700;margin:0 0 20px;">{title}</h2>
    {content}
    {cta}
    <hr style="border:none;border-top:1px solid #E2E8F0;margin:32px 0;">
    <p style="color:#94A3B8;font-size:11px;margin:0;line-height:1.6;">
      Sent by VAPTForge Enterprise &bull; {_get_sender_email()}<br>
      © {datetime.now().year} VAPTForge — Authorized Security Scanning Only.
    </p>
  </td></tr>
</table>
</td></tr></table></body></html>"""


def scan_completed_html(org, target, scan_id, critical, high, medium, low,
                         risk, duration_min, dashboard_url):
    rc = "#DC2626" if risk >= 7 else "#EA580C" if risk >= 4 else "#D97706"
    content = f"""
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:10px;padding:20px;margin-bottom:24px;">
      <p style="color:#64748B;font-size:11px;margin:0 0 4px;text-transform:uppercase;">SCAN TARGET</p>
      <p style="color:#1E40AF;font-size:15px;font-weight:600;margin:0;font-family:monospace;">{target}</p>
    </div>
    <div style="text-align:center;background:{'#FEF2F2' if risk>=7 else '#FFFBEB'};
      border:1px solid {rc}40;border-radius:10px;padding:20px;margin-bottom:24px;">
      <p style="color:#64748B;font-size:11px;margin:0 0 8px;text-transform:uppercase;">Overall Risk Score</p>
      <p style="color:{rc};font-size:48px;font-weight:800;margin:0;">{risk:.1f}<span style="font-size:18px;color:#94A3B8;">/10</span></p>
    </div>
    <p style="color:#475569;font-size:13px;">
      Scan completed in <strong>{duration_min} min</strong> &bull;
      ID: <code style="background:#F1F5F9;padding:2px 6px;border-radius:4px;">{scan_id[:8]}</code>
    </p>"""
    subj = f"[VAPTForge] Scan Complete — {target} | Risk: {risk:.1f}/10"
    return subj, _base_html(org, "Scan Completed", content, dashboard_url, "View Full Report")


def critical_alert_html(org, target, vuln_title, owasp, sev, endpoint, description, dashboard_url):
    content = f"""
    <div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:10px;padding:16px;margin-bottom:20px;">
      <p style="color:#DC2626;font-size:13px;font-weight:700;margin:0 0 4px;">⚠ {sev.upper()} SEVERITY</p>
      <p style="color:#7F1D1D;font-size:18px;font-weight:700;margin:0;">{vuln_title}</p>
    </div>
    <p style="color:#475569;font-size:13px;line-height:1.7;">{description[:400]}</p>
    <p style="color:#DC2626;font-size:13px;font-weight:600;">Immediate remediation recommended.</p>"""
    subj = f"[ALERT] {sev.upper()} Vulnerability: {vuln_title} — {target}"
    return subj, _base_html(org, "Critical Vulnerability Alert", content, dashboard_url, "Investigate Now")


def report_share_html(org, target, sender, message, report_url):
    msg_block = f"""<div style="background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:14px;margin:16px 0;">
      <p style="color:#64748B;font-size:11px;margin:0 0 4px;">MESSAGE FROM {sender.upper()}</p>
      <p style="color:#1E293B;font-size:13px;margin:0;">{message}</p>
    </div>""" if message else ""
    content = f"""
    <p style="color:#475569;font-size:14px;">
      <strong>{sender}</strong> from <strong style="color:#1E40AF;">{org}</strong>
      has shared a security assessment report with you.
    </p>
    {msg_block}
    <div style="background:#F8FAFC;border:1px solid #E2E8F0;border-radius:8px;padding:14px;margin:16px 0;">
      <p style="color:#64748B;font-size:11px;margin:0 0 4px;">TARGET</p>
      <p style="color:#1E40AF;font-size:14px;font-family:monospace;margin:0;">{target}</p>
    </div>"""
    subj = f"[VAPTForge] Security Assessment Report — {target}"
    return subj, _base_html(org, "Security Assessment Report", content, report_url, "Open Report")


def password_reset_html(reset_url: str, expiry_minutes: int = 30) -> tuple:
    content = f"""
    <p style="color:#475569;font-size:14px;line-height:1.7;">
      We received a request to reset the password for your VAPTForge account.
      Click the button below to set a new password. This link expires in
      <strong>{expiry_minutes} minutes</strong> and can only be used once.
    </p>
    <div style="background:#FEF9C3;border:1px solid #FDE68A;border-radius:8px;padding:12px 16px;margin:16px 0;font-size:12px;color:#92400E;">
      If you did not request a password reset, please ignore this email.
    </div>"""
    subj = "[VAPTForge] Password Reset Request"
    return subj, _base_html("VAPTForge", "Reset Your Password", content, reset_url, "Reset Password")


class EmailService:

    def __init__(self):
        from app.core.config import settings
        self.cfg = settings

    def _is_configured(self) -> bool:
        cfg = self.cfg
        return bool(
            cfg.SMTP_USER and cfg.SMTP_PASS
            and str(cfg.SMTP_USER).strip()
            and str(cfg.SMTP_PASS).strip()
        )

    def _validate_emails(self, emails: List[str]) -> List[str]:
        valid = [e.strip() for e in emails if EMAIL_RE.match(e.strip())]
        if not valid:
            raise ValueError("No valid email addresses provided")
        return valid

    async def send(
        self,
        recipients: List[str],
        subject: str,
        html_body: str,
        text_body: str = "",
        attachments: Optional[List[dict]] = None,
        retries: int = 3,
    ) -> dict:
        try:
            valid = self._validate_emails(recipients)
        except ValueError as e:
            return {"success": False, "message": str(e), "recipients": recipients}

        if not self._is_configured():
            logger.warning("Email not configured — SMTP_USER and SMTP_PASS required")
            return {"success": False, "message": "Email not configured", "recipients": valid, "dev_mode": True}

        # Use SendGrid HTTP API (works on Render free plan)
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, self._sendgrid_send, valid, subject, html_body, text_body or "", attachments or []
            )
            return result
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return {"success": False, "message": str(e), "recipients": valid}

    def _sendgrid_send(self, recipients, subject, html_body, text_body, attachments):
        import urllib.request
        import json

        api_key = str(self.cfg.SMTP_PASS).strip()
        sender_email = _get_sender_email()

        to_list = [{"email": r} for r in recipients]

        payload = {
            "personalizations": [{"to": to_list}],
            "from": {"email": sender_email, "name": SENDER_NAME},
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text_body or "Please view this email in HTML."},
                {"type": "text/html", "value": html_body},
            ],
        }

        # Add attachments if any
        if attachments:
            att_list = []
            for att in attachments:
                data = att.get("data", b"")
                if data:
                    att_list.append({
                        "content": base64.b64encode(data).decode(),
                        "filename": att.get("filename", "attachment"),
                        "type": att.get("mime", "application/octet-stream"),
                        "disposition": "attachment",
                    })
            if att_list:
                payload["attachments"] = att_list

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.sendgrid.com/v3/mail/send",
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                logger.info(f"SendGrid response: {resp.status} → {recipients}")
                return {"success": True, "message": "Email sent successfully", "recipients": recipients}
        except Exception as e:
            logger.error(f"SendGrid API error: {e}")
            raise

    def _strip_html(self, html: str) -> str:
        import re
        return re.sub(r"<[^>]+>", "", html).strip()

    async def send_scan_completed(self, recipients, org_name, target_url, scan_id,
                                   critical, high, medium, low, risk_score,
                                   duration_min, dashboard_url):
        subj, html = scan_completed_html(org_name, target_url, scan_id, critical,
                                          high, medium, low, risk_score, duration_min, dashboard_url)
        return await self.send(recipients, subj, html)

    async def send_critical_alert(self, recipients, org_name, target_url, vuln_title,
                                   owasp_category, severity, affected_endpoint,
                                   description, dashboard_url):
        subj, html = critical_alert_html(org_name, target_url, vuln_title,
                                          owasp_category, severity, affected_endpoint,
                                          description, dashboard_url)
        return await self.send(recipients, subj, html)

    async def send_report_share(self, recipients, org_name, target_url, sender_name,
                                 message, report_url,
                                 pdf_attachment=None, pdf_filename="report.pdf"):
        subj, html = report_share_html(org_name, target_url, sender_name, message, report_url)
        atts = []
        if pdf_attachment and isinstance(pdf_attachment, bytes) and pdf_attachment[:5] == b"%PDF-":
            atts.append({"filename": pdf_filename, "data": pdf_attachment, "mime": "application/pdf"})
        return await self.send(recipients, subj, html, attachments=atts)

    async def send_password_reset(self, recipient: str, reset_url: str, expiry_minutes: int = 30):
        subj, html = password_reset_html(reset_url, expiry_minutes)
        return await self.send([recipient], subj, html)


email_service = EmailService()