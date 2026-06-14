"""
VAPTForge Email Service — Production SMTP with Gmail support
Sender: vaptplatform@gmail.com
Supports: Gmail App Password, custom SMTP, retry, validation, PDF attachment
"""
import asyncio
import logging
import re
import smtplib
import ssl
import os
from datetime import datetime, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional
from app.core.config import settings

logger = logging.getLogger("vapt.email")
EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

SENDER_NAME  = "VAPTForge Security"
# NOTE: _get_sender_email() is set dynamically per-send from settings.SMTP_USER
# to avoid "Address not found" errors when SMTP_USER != from address
_FALLBACK_EMAIL = "vaptnotify@gmail.com"

def _get_sender_email() -> str:
    """Always return the current SMTP_USER to avoid 'Address not found' mismatches."""
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
    <table width="100%" cellpadding="0" cellspacing="8" style="margin-bottom:24px;">
      <tr>
        <td width="25%" style="text-align:center;background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:14px;">
          <p style="color:#94A3B8;font-size:10px;margin:0 0 4px;text-transform:uppercase;">Critical</p>
          <p style="color:#DC2626;font-size:26px;font-weight:800;margin:0;">{critical}</p>
        </td>
        <td width="25%" style="text-align:center;background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;padding:14px;">
          <p style="color:#94A3B8;font-size:10px;margin:0 0 4px;text-transform:uppercase;">High</p>
          <p style="color:#EA580C;font-size:26px;font-weight:800;margin:0;">{high}</p>
        </td>
        <td width="25%" style="text-align:center;background:#FFFBEB;border:1px solid #FDE68A;border-radius:8px;padding:14px;">
          <p style="color:#94A3B8;font-size:10px;margin:0 0 4px;text-transform:uppercase;">Medium</p>
          <p style="color:#D97706;font-size:26px;font-weight:800;margin:0;">{medium}</p>
        </td>
        <td width="25%" style="text-align:center;background:#EFF6FF;border:1px solid #BFDBFE;border-radius:8px;padding:14px;">
          <p style="color:#94A3B8;font-size:10px;margin:0 0 4px;text-transform:uppercase;">Low</p>
          <p style="color:#2563EB;font-size:26px;font-weight:800;margin:0;">{low}</p>
        </td>
      </tr>
    </table>
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
    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:16px;">
      <tr><td style="padding:8px 0;color:#64748B;font-size:12px;width:100px;">OWASP</td>
          <td style="padding:8px 0;color:#1E293B;font-size:13px;">{owasp}</td></tr>
      <tr><td style="padding:8px 0;color:#64748B;font-size:12px;">Target</td>
          <td style="padding:8px 0;color:#1E40AF;font-size:12px;font-family:monospace;">{target}</td></tr>
      <tr><td style="padding:8px 0;color:#64748B;font-size:12px;">Endpoint</td>
          <td style="padding:8px 0;color:#1E40AF;font-size:12px;font-family:monospace;">{endpoint[:80]}</td></tr>
    </table>
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
    </div>
    <p style="color:#475569;font-size:13px;">
      The full report with findings, risk analysis, and remediation guidance is
      {"attached as PDF and " if report_url else ""}available via the link below.
    </p>"""
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
      Your password will not be changed.
    </div>"""
    subj = "[VAPTForge] Password Reset Request"
    return subj, _base_html("VAPTForge", "Reset Your Password", content, reset_url, "Reset Password")


class EmailService:

    def __init__(self):
        from app.core.config import settings
        self.cfg = settings

    def _is_smtp_configured(self) -> bool:
        """Return True only when all required SMTP settings are present."""
        cfg = self.cfg
        return bool(
            cfg.SMTP_HOST
            and cfg.SMTP_USER
            and cfg.SMTP_PASS
            and str(cfg.SMTP_HOST).strip()
            and str(cfg.SMTP_USER).strip()
            and str(cfg.SMTP_PASS).strip()
        )

    def _validate_emails(self, emails: List[str]) -> List[str]:
        valid = [e.strip() for e in emails if EMAIL_RE.match(e.strip())]
        if not valid:
            raise ValueError("No valid email addresses provided")
        if len(valid) > 20:
            raise ValueError("Maximum 20 recipients per send")
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

        # ── DEV MODE: SMTP not configured ──────────────────────────────────
        if not self._is_smtp_configured():
            msg = (
                "SMTP not configured — email NOT sent. "
                "Add SMTP_HOST, SMTP_USER, SMTP_PASS to backend/.env "
                f"(sender: {_get_sender_email()})"
            )
            logger.warning(
                f"\n{'='*60}\n"
                f"[DEV MODE — EMAIL NOT SENT]\n"
                f"To: {valid}\nSubject: {subject}\n"
                f"Set SMTP_HOST + SMTP_USER + SMTP_PASS to send real emails.\n"
                f"For Gmail: use App Password at myaccount.google.com/apppasswords\n"
                f"{'='*60}"
            )
            # Return explicit failure so frontend knows email was NOT sent
            return {
                "success": False,
                "message": msg,
                "recipients": valid,
                "dev_mode": True,
            }

        # ── REAL SMTP ───────────────────────────────────────────────────────
        last_err = None
        for attempt in range(retries):
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._smtp_send,
                    valid, subject, html_body,
                    text_body or self._strip_html(html_body),
                    attachments or [],
                )
                logger.info(f"Email sent OK → {valid} | {subject[:60]}")
                return {"success": True, "message": "Email sent successfully", "recipients": valid}
            except smtplib.SMTPAuthenticationError as e:
                last_err = f"SMTP authentication failed — check SMTP_USER and SMTP_PASS: {e}"
                logger.error(last_err)
                break  # No point retrying auth failures
            except smtplib.SMTPRecipientsRefused as e:
                last_err = f"Recipient refused by SMTP server: {e}"
                logger.error(last_err)
                break
            except smtplib.SMTPSenderRefused as e:
                last_err = (
                    f"Sender address refused by SMTP server: {e}. "
                    f"Ensure SMTP_USER ({self.cfg.SMTP_USER}) matches the Gmail account you are authenticating as. "
                    f"Gmail does not allow sending from an address that differs from the authenticated account."
                )
                logger.error(last_err)
                break  # No point retrying sender refused
            except smtplib.SMTPException as e:
                last_err = f"SMTP error: {e}"
                logger.error(f"SMTP error on attempt {attempt+1}/{retries}: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)
            except Exception as e:
                last_err = str(e)
                logger.warning(f"Email attempt {attempt+1}/{retries} failed: {e}")
                if attempt < retries - 1:
                    await asyncio.sleep(2 ** attempt)

        logger.error(f"Email failed after {retries} attempts: {last_err}")
        return {"success": False, "message": f"Send failed: {last_err}", "recipients": valid}

    def _smtp_send(self, recipients, subject, html_body, text_body, attachments):
        cfg = self.cfg

        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"]    = f"{SENDER_NAME} <{_get_sender_email()}>"
        msg["To"]      = ", ".join(recipients)
        msg["X-Mailer"] = "VAPTForge-Enterprise/3.4.1"

        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText(text_body, "plain", "utf-8"))
        alt.attach(MIMEText(html_body, "html",  "utf-8"))
        msg.attach(alt)

        for att in attachments:
            # Validate PDF attachment before sending
            data = att.get("data", b"")
            if att.get("mime") == "application/pdf" and data:
                if not data[:5] == b"%PDF-":
                    logger.warning("Skipping attachment — not a valid PDF")
                    continue
            mime_type = att.get("mime", "application/octet-stream")
            part = MIMEBase(*mime_type.split("/", 1))
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=att["filename"])
            msg.attach(part)

        ctx = ssl.create_default_context()
        port = int(cfg.SMTP_PORT or 587)
        host = str(cfg.SMTP_HOST).strip()
        user = str(cfg.SMTP_USER).strip()
        pw   = str(cfg.SMTP_PASS).strip()
        logger.info(f"SMTP LOGIN TRY → {user} / {len(pw)} chars password")
        logger.info(f"SMTP HOST={host}, PORT={port}")

        logger.info(f"SMTP connecting: {host}:{port} as {user}")

        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=30) as srv:
                srv.login(user, pw)
                srv.sendmail(_get_sender_email(), recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=30) as srv:
                srv.ehlo()
                srv.starttls(context=ctx)
                srv.ehlo()
                srv.login(user, pw)
                srv.sendmail(_get_sender_email(), recipients, msg.as_string())

    def _strip_html(self, html: str) -> str:
        import re
        return re.sub(r"<[^>]+>", "", html).strip()

    # ── High-level send helpers ──────────────────────────────────────────────

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
        if pdf_attachment:
            # Validate PDF bytes before attaching
            if isinstance(pdf_attachment, bytes) and pdf_attachment[:5] == b"%PDF-":
                atts.append({
                    "filename": pdf_filename,
                    "data": pdf_attachment,
                    "mime": "application/pdf",
                })
            else:
                logger.warning("PDF attachment invalid — sending email without attachment")
        return await self.send(recipients, subj, html, attachments=atts)

    async def send_password_reset(self, recipient: str, reset_url: str,
                                   expiry_minutes: int = 30):
        subj, html = password_reset_html(reset_url, expiry_minutes)
        return await self.send([recipient], subj, html)


email_service = EmailService()
