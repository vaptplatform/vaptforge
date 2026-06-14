"""
VAPTForge Enterprise — Professional Report Generator v4.0
Produces client-ready HTML, PDF, and JSON reports.
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
import re as _re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("vapt.reports")

SEV_COLOR  = {"critical":"#DC2626","high":"#EA580C","medium":"#D97706","low":"#2563EB","info":"#6B7280"}
SEV_BG     = {"critical":"#FEF2F2","high":"#FFF7ED","medium":"#FFFBEB","low":"#EFF6FF","info":"#F9FAFB"}
SEV_BORDER = {"critical":"#FECACA","high":"#FED7AA","medium":"#FDE68A","low":"#BFDBFE","info":"#E5E7EB"}

_SAST_DAST   = _re.compile(r"^\[(SAST|DAST)\]\s*", _re.IGNORECASE)
_SEV_RANK    = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

_TITLE_SYNONYMS = [
    (_re.compile(r"missing\s+(strict.transport.security\s*\(hsts\)|hsts)\s*(header)?", _re.I), "Missing HSTS Header"),
    (_re.compile(r"missing\s+x.frame.options\s*(header)?", _re.I), "Missing X-Frame-Options Header"),
    (_re.compile(r"missing\s+(content.security.policy|csp)\s*(header)?", _re.I), "Missing Content-Security-Policy Header"),
    (_re.compile(r"missing\s+x.content.type.options\s*(header)?", _re.I), "Missing X-Content-Type-Options Header"),
    (_re.compile(r"sql\s*injection", _re.I), "SQL Injection"),
    (_re.compile(r"cross.site\s+scripting|xss", _re.I), "Cross-Site Scripting (XSS)"),
    (_re.compile(r"cross.site\s+request\s+forgery|csrf", _re.I), "Cross-Site Request Forgery (CSRF)"),
    (_re.compile(r"(dangerous\s+http\s+method[s]?\s*(enabled)?:?\s*TRACE|http\s+TRACE\s+(method|enabled))", _re.I), "Dangerous HTTP Methods Enabled: TRACE"),
    (_re.compile(r"open\s+redirect", _re.I), "Open Redirect"),
    (_re.compile(r"clickjacking", _re.I), "Clickjacking"),
    (_re.compile(r"directory\s+(listing|traversal)", _re.I), "Directory Listing / Path Traversal"),
    (_re.compile(r"insecure\s+cookie", _re.I), "Insecure Cookie Configuration"),
]


def _normalize_title(title: str) -> str:
    t = _SAST_DAST.sub("", title).strip()
    for pattern, canonical in _TITLE_SYNONYMS:
        if pattern.search(t):
            return canonical
    return t


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    u = url.rstrip("/")
    base = u.split("?")[0]
    return base.lower()


def _cvss_rating(score: float) -> tuple:
    if score >= 9.0: return ("CRITICAL", "#DC2626")
    if score >= 7.0: return ("HIGH",     "#EA580C")
    if score >= 4.0: return ("MEDIUM",   "#D97706")
    if score >  0.0: return ("LOW",      "#2563EB")
    return ("NONE", "#6B7280")


def _sv(f) -> str:
    v = getattr(f, "severity", None) or (f.get("severity","info") if isinstance(f,dict) else "info")
    return (v.value if hasattr(v,"value") else str(v)).lower()


def _g(f, key, default=""):
    if isinstance(f, dict): v = f.get(key, default)
    else: v = getattr(f, key, default)
    if v is None: return default
    return v.value if hasattr(v,"value") else v


def _trim_http(text: str, max_lines: int = 30) -> str:
    if not text:
        return ""
    text = _re.sub(r"\n{3,}", "\n\n", text.strip())
    lines = text.split("\n")
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"… [{len(lines)-max_lines} more lines truncated]"]
    return "\n".join(lines)


def _escape_html(s: str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
             .replace('"',"&quot;").replace("'","&#39;"))


# ── ReportLab XML sanitizer ───────────────────────────────────────────────────
def _rl_safe(text: str) -> str:
    """
    Strip all HTML and produce plain text safe for ReportLab Paragraph XML.

    Strategy: decode HTML entities → strip all tags → re-escape for XML.
    This is the only reliable approach when input HTML may contain partial
    or nested tags (e.g. fragments extracted via regex from the full report).
    """
    if not text:
        return ""
    # 1. Normalize line breaks to spaces before stripping
    text = _re.sub(r'<br\s*/?>', ' ', text, flags=_re.I)
    # 2. Decode common HTML entities
    text = (text
            .replace('&amp;',  '&')
            .replace('&lt;',   '<')
            .replace('&gt;',   '>')
            .replace('&quot;', '"')
            .replace('&#39;',  "'")
            .replace('&nbsp;', ' ')
            .replace('&bull;', '\u2022')
            .replace('&#x2022;', '\u2022')
            .replace('&#x2014;', '\u2014')
            .replace('&mdash;', '\u2014')
            .replace('&ndash;', '\u2013'))
    # 3. Strip ALL HTML tags — safest for fragments captured by regex
    text = _re.sub(r'<[^>]+>', '', text)
    # 4. Collapse extra whitespace
    text = _re.sub(r'[ \t]+', ' ', text)
    text = _re.sub(r'\n{3,}', '\n\n', text)
    # 5. Re-escape special XML characters for ReportLab
    text = (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;'))
    return text.strip()


def _rl_para(text: str, style, max_chars: int = 800):
    """
    Build a ReportLab Paragraph safely, with a double fallback:
      1. Try _rl_safe(text) — strips all HTML
      2. If that still fails, use plain repr of text
    Never raises; always returns a Paragraph.
    """
    from reportlab.platypus import Paragraph
    clean = _rl_safe(text)[:max_chars]
    try:
        return Paragraph(clean, style)
    except Exception:
        # Last-resort: ascii-safe only
        ascii_safe = clean.encode('ascii', errors='replace').decode('ascii')
        try:
            return Paragraph(ascii_safe, style)
        except Exception:
            return Paragraph("(content could not be rendered)", style)
# ─────────────────────────────────────────────────────────────────────────────


class ReportGenerator:

    def __init__(self, reports_dir: str = "./reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    # ══════════════════════════════════════════════════════════════════════════
    # DEDUPLICATION
    # ══════════════════════════════════════════════════════════════════════════

    def _deduplicate(self, findings: list) -> list:
        exact: dict = {}
        for f in findings:
            raw_title  = _g(f, "title", "")
            norm_title = _normalize_title(raw_title)
            url        = _g(f, "affected_url", "") or _g(f, "url", "")
            norm_url   = _normalize_url(url)
            owasp      = _g(f, "owasp_category", "")
            cwe        = _g(f, "cwe", "")
            exact_key  = (norm_title.lower(), norm_url, owasp or cwe)
            raw_method = _SAST_DAST.match(raw_title)
            meth = raw_method.group(1).upper() if raw_method else "DAST"

            if exact_key not in exact:
                entry = dict(f) if isinstance(f, dict) else {
                    k: _g(f, k) for k in [
                        "id","scan_id","owasp_category","owasp_name","title",
                        "description","severity","status","affected_url",
                        "affected_parameter","http_method","risk_score",
                        "cvss_score","confidence","evidence","remediation",
                        "references","is_false_positive","detected_at","cwe",
                    ]
                }
                entry["title"]              = norm_title
                entry["_detection_methods"] = [meth]
                entry["_affected_urls"]     = [url] if url else []
                entry["_all_evidence"]      = [_g(f,"evidence",{})]
                exact[exact_key]            = entry
            else:
                existing = exact[exact_key]
                if meth not in existing.get("_detection_methods", []):
                    existing.setdefault("_detection_methods", []).append(meth)
                if url and url not in existing.get("_affected_urls", []):
                    existing.setdefault("_affected_urls", []).append(url)
                ev = _g(f, "evidence", {})
                if ev:
                    existing.setdefault("_all_evidence", []).append(ev)
                if _g(f,"risk_score",0) > _g(existing,"risk_score",0):
                    existing["risk_score"] = _g(f,"risk_score",0)
                if _g(f,"cvss_score",None) and (
                    not _g(existing,"cvss_score",None)
                    or float(_g(f,"cvss_score",0)) > float(_g(existing,"cvss_score",0))
                ):
                    existing["cvss_score"] = _g(f,"cvss_score",None)
                if _SEV_RANK.get(_sv(f),9) < _SEV_RANK.get(_sv(existing),9):
                    existing["severity"] = _g(f,"severity","info")

        grouped: dict = {}
        for entry in exact.values():
            norm_title = entry.get("title","").lower()
            owasp      = entry.get("owasp_category","")
            group_key  = (norm_title, owasp)
            if group_key not in grouped:
                grouped[group_key] = entry
            else:
                master = grouped[group_key]
                for m in entry.get("_detection_methods", []):
                    if m not in master.get("_detection_methods", []):
                        master.setdefault("_detection_methods", []).append(m)
                for u in entry.get("_affected_urls", []):
                    if u and u not in master.get("_affected_urls", []):
                        master.setdefault("_affected_urls", []).append(u)
                master.setdefault("_all_evidence",[]).extend(entry.get("_all_evidence",[]))
                if _SEV_RANK.get(_sv(entry),9) < _SEV_RANK.get(_sv(master),9):
                    master["severity"] = entry.get("severity","info")
                if entry.get("risk_score",0) > master.get("risk_score",0):
                    master["risk_score"] = entry.get("risk_score",0)
                if entry.get("cvss_score") and (
                    not master.get("cvss_score")
                    or float(entry.get("cvss_score",0)) > float(master.get("cvss_score",0))
                ):
                    master["cvss_score"] = entry.get("cvss_score")

        return list(grouped.values())

    # ══════════════════════════════════════════════════════════════════════════
    # JSON
    # ══════════════════════════════════════════════════════════════════════════

    def generate_json(self, scan_data: dict, findings: list) -> dict:
        findings = self._deduplicate(findings)
        summary  = self._executive_summary(scan_data, findings)
        return {
            "report_format":    "json",
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "platform":         "VAPTForge Enterprise v4.0.0",
            "scan": {
                "id":             scan_data.get("id",""),
                "target_url":     scan_data.get("target_url",""),
                "profile":        str(scan_data.get("profile","")),
                "status":         str(scan_data.get("status","")),
                "started_at":     str(scan_data.get("started_at","")),
                "completed_at":   str(scan_data.get("completed_at","")),
                "urls_crawled":   scan_data.get("urls_crawled",0),
                "total_requests": scan_data.get("total_requests",0),
            },
            "organization":     {"name": scan_data.get("org_name",""), "id": scan_data.get("org_id","")},
            "executive_summary": summary,
            "owasp_coverage":   self._owasp_summary(findings),
            "findings":         [self._finding_dict(f) for f in findings],
            "risk_matrix":      self._risk_matrix(findings),
        }

    def save_json(self, data: dict, scan_id: str) -> str:
        p = self.reports_dir / f"report_{scan_id[:8]}.json"
        with open(p,"w") as f:
            json.dump(data, f, indent=2, default=str)
        return str(p)

    def invalidate_cache(self, scan_id: str) -> None:
        """Delete cached report files for a scan so they rebuild on next request."""
        prefix = f"report_{scan_id[:8]}"
        for ext in (".pdf", ".html", ".json"):
            p = self.reports_dir / f"{prefix}{ext}"
            if p.exists():
                p.unlink()
                logger.info(f"Cache invalidated: {p}")

    # ══════════════════════════════════════════════════════════════════════════
    # HTML
    # ══════════════════════════════════════════════════════════════════════════

    def generate_html(self, scan_data: dict, findings: list) -> str:
        findings = self._deduplicate(findings)
        summary  = self._executive_summary(scan_data, findings)
        owasp    = self._owasp_summary(findings)
        _owasp_keys = ['A01','A02','A03','A04','A05','A06','A07','A08','A09','A10']
        _counts  = [owasp.get(k,{}).get('count',0) if isinstance(owasp.get(k,{}),dict) else 0 for k in _owasp_keys]

        scan_id    = str(scan_data.get("id",""))[:8]
        target     = scan_data.get("target_url","")
        org        = scan_data.get("org_name","")
        risk       = scan_data.get("risk_score",0) or 0
        gen_date   = datetime.now(timezone.utc).strftime("%B %d, %Y")
        gen_dt     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        risk_color = "#DC2626" if risk>=7 else "#EA580C" if risk>=4 else "#D97706"

        crit  = summary.get("critical",0)
        high  = summary.get("high",0)
        med   = summary.get("medium",0)
        low   = summary.get("low",0)
        info_ = summary.get("info",0)
        total = summary.get("total",0)

        findings_sorted = sorted(findings, key=lambda f: _SEV_RANK.get(_sv(f),5))
        findings_html   = "".join(self._render_finding_block(f,i+1) for i,f in enumerate(findings_sorted))
        owasp_html      = self._render_owasp_table(owasp)
        toc_html        = self._render_toc(findings_sorted)
        sev_chart_svg   = self._render_sev_chart(crit, high, med, low, info_)
        owasp_chart_svg = self._render_owasp_bar_chart(_counts, _owasp_keys)
        priority_matrix = self._render_priority_matrix(findings_sorted)

        dedup_note = f"{total} unique findings (duplicates merged)" if total > 0 else "No findings"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>VAPT Report — {_escape_html(target)}</title>
{self._css()}
</head>
<body>

<div class="cover">
  <div class="cover-logo">■ <span style="color:#60A5FA;font-weight:900;letter-spacing:2px;">VAPTFORGE</span>&nbsp; Enterprise</div>
  <div style="margin-top:56px;">
    <div class="confidential-tag">CONFIDENTIAL — AUTHORIZED USE ONLY</div>
    <h1 class="cover-h1">Security Assessment<span class="cover-sub">Vulnerability &amp; Penetration Testing Report</span></h1>
  </div>
  <div class="cover-meta">
    <div class="cover-meta-item"><label>Target System</label><value>{_escape_html(target)}</value></div>
    <div class="cover-meta-item"><label>Organization</label><value>{_escape_html(org) or "—"}</value></div>
    <div class="cover-meta-item"><label>Report Date</label><value>{gen_date}</value></div>
    <div class="cover-meta-item"><label>Report ID</label><value>{scan_id}</value></div>
    <div class="cover-meta-item"><label>Classification</label><value>CONFIDENTIAL</value></div>
    <div class="cover-meta-item"><label>Generated</label><value>{gen_dt}</value></div>
  </div>
  <div class="cover-risk-panel">
    <div class="cover-risk-score">
      <div class="cover-risk-num" style="color:{risk_color};">{risk:.1f}<span class="cover-risk-denom">/10</span></div>
      <div class="cover-risk-label">Overall Risk Score</div>
    </div>
    <div class="cover-risk-breakdown">
      <div class="cover-risk-item" style="color:#FCA5A5;"><span class="cbig">{crit}</span><span class="clab">Critical</span></div>
      <div class="cover-risk-item" style="color:#FDB87D;"><span class="cbig">{high}</span><span class="clab">High</span></div>
      <div class="cover-risk-item" style="color:#FDE68A;"><span class="cbig">{med}</span><span class="clab">Medium</span></div>
      <div class="cover-risk-item" style="color:#93C5FD;"><span class="cbig">{low}</span><span class="clab">Low</span></div>
      <div class="cover-risk-item" style="color:#94A3B8;"><span class="cbig">{info_}</span><span class="clab">Info</span></div>
    </div>
  </div>
  <div class="cover-footer">{dedup_note} &nbsp;·&nbsp; VAPTForge Enterprise v4.0.0</div>
</div>

<div class="page">
  <div class="section-header" id="s1"><div class="section-num">01</div><div class="section-title">Executive Summary</div></div>
  <div class="exec-box"><p class="exec-text">{summary.get("executive_text","")}</p></div>
  <div class="risk-grid">
    <div class="risk-card" style="background:#FEF2F2;border-color:#FECACA;"><div class="risk-card-num" style="color:#DC2626;">{crit}</div><div class="risk-card-label" style="color:#DC2626;">Critical</div></div>
    <div class="risk-card" style="background:#FFF7ED;border-color:#FED7AA;"><div class="risk-card-num" style="color:#EA580C;">{high}</div><div class="risk-card-label" style="color:#EA580C;">High</div></div>
    <div class="risk-card" style="background:#FFFBEB;border-color:#FDE68A;"><div class="risk-card-num" style="color:#D97706;">{med}</div><div class="risk-card-label" style="color:#D97706;">Medium</div></div>
    <div class="risk-card" style="background:#EFF6FF;border-color:#BFDBFE;"><div class="risk-card-num" style="color:#2563EB;">{low}</div><div class="risk-card-label" style="color:#2563EB;">Low</div></div>
    <div class="risk-card" style="background:#F9FAFB;border-color:#E5E7EB;"><div class="risk-card-num" style="color:#6B7280;">{info_}</div><div class="risk-card-label" style="color:#6B7280;">Info</div></div>
  </div>
  <div class="chart-row">
    <div class="chart-box"><h4 class="chart-title">Severity Distribution</h4><div class="chart-container">{sev_chart_svg}</div></div>
    <div class="chart-box"><h4 class="chart-title">OWASP Top 10 Coverage</h4><div class="chart-container">{owasp_chart_svg}</div></div>
  </div>
  <div class="section-header" id="s2"><div class="section-num">02</div><div class="section-title">Remediation Priority Matrix</div></div>
  {priority_matrix}
  <div class="section-header" id="s3"><div class="section-num">03</div><div class="section-title">OWASP Top 10 Coverage</div></div>
  {owasp_html}
  <div class="section-header" id="s4"><div class="section-num">04</div><div class="section-title">Findings Index</div></div>
  <div class="toc">{toc_html}</div>
  <div class="section-header" id="s5"><div class="section-num">05</div><div class="section-title">Detailed Findings with Evidence</div></div>
  {findings_html if findings_html else '<div class="exec-box"><p class="exec-text">No findings recorded for this scan.</p></div>'}
  <div class="report-footer">
    <span>VAPTForge Enterprise v4.0.0</span><span>·</span>
    <span>Generated {gen_dt}</span><span>·</span>
    <span>CONFIDENTIAL — NOT FOR DISTRIBUTION</span>
  </div>
</div>

<script>
document.querySelectorAll('.ev-toggle').forEach(function(btn) {{
  btn.addEventListener('click', function() {{
    var target = document.getElementById(btn.dataset.target);
    if (!target) return;
    var hidden = target.style.display === 'none';
    target.style.display = hidden ? 'block' : 'none';
    btn.textContent = hidden ? '▲ Hide' : '▼ Show';
  }});
}});
</script>
</body>
</html>"""

    def save_html(self, html: str, scan_id: str) -> str:
        p = self.reports_dir / f"report_{scan_id[:8]}.html"
        with open(str(p),"w",encoding="utf-8") as f:
            f.write(html)
        return str(p)

    # ══════════════════════════════════════════════════════════════════════════
    # PDF
    # ══════════════════════════════════════════════════════════════════════════

    def generate_pdf(self, html_content: str, scan_id: str) -> Optional[str]:
        """
        Generate PDF via ReportLab directly — no WeasyPrint.
        WeasyPrint is slow (GTK/Pango startup + font loading = 10-30s) and
        unreliable across environments. ReportLab builds the same content in
        under 1 second.

        Caching: if the PDF already exists and is newer than this hour,
        return it immediately without rebuilding.
        """
        pdf_path = self.reports_dir / f"report_{scan_id[:8]}.pdf"

        # ── Cache: serve existing PDF if fresh (< 1 hour old) ────────────────
        if pdf_path.exists() and pdf_path.stat().st_size > 1024:
            import time
            age_seconds = time.time() - pdf_path.stat().st_mtime
            if age_seconds < 3600:
                with open(str(pdf_path), "rb") as pf:
                    if pf.read(5) == b"%PDF-":
                        logger.info(f"PDF cache hit: {pdf_path} ({age_seconds:.0f}s old)")
                        return str(pdf_path)

        # ── Build fresh PDF via ReportLab ─────────────────────────────────────
        try:
            return self._generate_pdf_reportlab(html_content, scan_id, pdf_path)
        except Exception as e:
            logger.error(f"ReportLab PDF generation failed: {e}", exc_info=True)
        return None

    def _generate_pdf_reportlab(self, html_content, scan_id, pdf_path):
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm, mm
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable, PageBreak,
                                        KeepTogether)
        from reportlab.lib.enums import TA_CENTER

        W, H = A4
        gen_dt = datetime.now(timezone.utc).strftime("%B %d, %Y")

        def page_template(canvas, doc):
            if doc.page == 1:
                return
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#E2E8F0"))
            canvas.setLineWidth(0.5)
            canvas.line(2*cm, H-1.4*cm, W-2*cm, H-1.4*cm)
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#94A3B8"))
            canvas.drawString(2*cm, H-1.1*cm, "VAPTForge Enterprise — CONFIDENTIAL")
            canvas.drawRightString(W-2*cm, H-1.1*cm, f"Page {doc.page}")
            canvas.line(2*cm, 1.4*cm, W-2*cm, 1.4*cm)
            canvas.drawString(2*cm, 0.9*cm, f"Generated {gen_dt}")
            canvas.drawRightString(W-2*cm, 0.9*cm, "NOT FOR DISTRIBUTION")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(pdf_path), pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.2*cm, bottomMargin=2.2*cm,
        )

        C = {
            "dark":   colors.HexColor("#0F172A"),
            "slate":  colors.HexColor("#475569"),
            "muted":  colors.HexColor("#94A3B8"),
            "blue":   colors.HexColor("#1E40AF"),
            "crit":   colors.HexColor("#DC2626"),
            "high":   colors.HexColor("#EA580C"),
            "med":    colors.HexColor("#D97706"),
            "low":    colors.HexColor("#2563EB"),
            "line":   colors.HexColor("#E2E8F0"),
            "bgcard": colors.HexColor("#F8FAFC"),
        }

        def S(name, **kw):
            base = {
                "title":  dict(fontSize=26, fontName="Helvetica-Bold", textColor=C["dark"], spaceAfter=6, leading=32),
                "h1":     dict(fontSize=14, fontName="Helvetica-Bold", textColor=C["dark"], spaceBefore=18, spaceAfter=8, leading=18),
                "body":   dict(fontSize=9,  fontName="Helvetica", textColor=C["slate"], spaceAfter=5, leading=14),
                "small":  dict(fontSize=8,  fontName="Helvetica", textColor=C["muted"], spaceAfter=3, leading=11),
                "footer": dict(fontSize=7,  fontName="Helvetica", textColor=C["muted"], alignment=TA_CENTER),
            }[name]
            base.update(kw)
            return ParagraphStyle(name, **base)

        SEV_RL = {
            "critical": (colors.HexColor("#FEF2F2"), C["crit"]),
            "high":     (colors.HexColor("#FFF7ED"), C["high"]),
            "medium":   (colors.HexColor("#FFFBEB"), C["med"]),
            "low":      (colors.HexColor("#EFF6FF"), C["low"]),
            "info":     (colors.HexColor("#F9FAFB"), C["muted"]),
        }

        def extract(pattern, default=""):
            m = _re.search(pattern, html_content, _re.I | _re.S)
            return m.group(1).strip() if m else default

        target = extract(r'<value>([^<]{3,200})</value>', "Unknown Target")

        story = []

        # ── Cover ────────────────────────────────────────────────────────────
        story.append(Spacer(1, 3*cm))
        story.append(Paragraph("VAPTForge Enterprise", ParagraphStyle(
            "brand", fontSize=11, fontName="Helvetica-Bold", textColor=C["blue"], spaceAfter=20
        )))
        story.append(Paragraph("Security Assessment", S("title")))
        story.append(Paragraph(
            "Vulnerability &amp; Penetration Testing Report",
            ParagraphStyle("sub", fontSize=16, fontName="Helvetica",
                           textColor=C["slate"], spaceAfter=24, leading=20)
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=C["line"], spaceAfter=20))
        mt = Table(
            [["Report ID", scan_id[:8], "Generated", gen_dt],
             ["Target",    target[:60], "Classification", "CONFIDENTIAL"]],
            colWidths=[2.5*cm, 7*cm, 3*cm, 4.5*cm]
        )
        mt.setStyle(TableStyle([
            ("FONTNAME",       (0,0),(-1,-1), "Helvetica"),
            ("FONTNAME",       (0,0),(0,-1),  "Helvetica-Bold"),
            ("FONTNAME",       (2,0),(2,-1),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0),(-1,-1), 9),
            ("TEXTCOLOR",      (0,0),(-1,-1), C["slate"]),
            ("ROWBACKGROUNDS", (0,0),(-1,-1), [colors.white, C["bgcard"]]),
            ("TOPPADDING",     (0,0),(-1,-1), 6),
            ("BOTTOMPADDING",  (0,0),(-1,-1), 6),
            ("LEFTPADDING",    (0,0),(-1,-1), 8),
        ]))
        story.append(mt)
        story.append(Spacer(1, 1*cm))
        story.append(Paragraph(
            'CONFIDENTIAL \u2022 AUTHORIZED USE ONLY',
            ParagraphStyle("conf", fontSize=9, fontName="Helvetica-Bold",
                           textColor=C["crit"], spaceAfter=0)
        ))
        story.append(PageBreak())

        # ── Executive Summary ─────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", S("h1")))
        story.append(HRFlowable(width="100%", thickness=2, color=C["blue"], spaceAfter=12))

        # FIX: use greedy+lazy combo and _rl_para for safe rendering
        exec_raw = extract(r'class="exec-text"[^>]*>([\s\S]*?)</p>', "")
        if exec_raw:
            story.append(_rl_para(exec_raw, S("body"), max_chars=800))

        story.append(Spacer(1, 0.5*cm))

        # ── Detailed Findings ─────────────────────────────────────────────────
        story.append(Paragraph("Detailed Findings", S("h1")))
        story.append(HRFlowable(width="100%", thickness=2, color=C["blue"], spaceAfter=12))

        finding_blocks = _re.findall(
            r'<div class="finding"[^>]*>(.*?)(?=<div class="finding"|<div class="report-footer")',
            html_content, _re.S
        )

        if finding_blocks:
            for i, block in enumerate(finding_blocks[:60]):
                def t(p, d=""):
                    m = _re.search(p, block, _re.S)
                    return (m.group(1).strip() if m else d)[:200]

                f_title = t(r'class="finding-title"[^>]*>([^<]+)', f"Finding #{i+1}")
                f_sev   = t(r'class="sev-badge"[^>]*>([^<]+)', "info").lower().strip()
                f_owasp = t(r'class="meta-val"[^>]*>([A-Z][0-9]{2}[^<]{0,60})', "")
                f_cvss  = t(r'CVSS\s+(\d+\.\d+)', "")

                # FIX: extract raw HTML then sanitize via _rl_safe
                f_desc_raw = t(r'<h4[^>]*>Description</h4>[\s\S]*?<p[^>]*>([\s\S]{20,600}?)</p>', "")
                f_rem_raw  = t(r'<h4[^>]*>Remediation</h4>[\s\S]*?<p[^>]*>([\s\S]{10,500}?)</p>', "")
                f_desc = _rl_safe(f_desc_raw)
                f_rem  = _rl_safe(f_rem_raw)

                confirmed = "CONFIRMED" in block
                sast_only = "SAST</span>" in block and "DAST</span>" not in block
                both_tag  = "CONFIRMED BY SAST + DAST" if confirmed else ("SAST" if sast_only else "DAST")

                sev_bg, sev_col = SEV_RL.get(f_sev, (C["bgcard"], C["muted"]))
                cvss_part = f"  CVSS {f_cvss}" if f_cvss else ""

                keep = []

                # FIX: sanitize title before embedding in Paragraph XML
                safe_title = _rl_safe(f_title)
                hdata = [[
                    _rl_para(
                        f"#{i+1:03d}  {safe_title}",
                        ParagraphStyle("fh", fontSize=10, fontName="Helvetica-Bold",
                                       textColor=C["dark"], leading=13),
                        max_chars=160,
                    ),
                    Paragraph(
                        f"{f_sev.upper()}{cvss_part}  [{both_tag}]",
                        ParagraphStyle("fs", fontSize=8, fontName="Helvetica-Bold",
                                       textColor=sev_col, leading=11, alignment=TA_CENTER)
                    ),
                ]]
                ht = Table(hdata, colWidths=["*", 4*cm])
                ht.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(-1,-1), sev_bg),
                    ("TOPPADDING",    (0,0),(-1,-1), 9),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 9),
                    ("LEFTPADDING",   (0,0),(0,-1),  12),
                    ("RIGHTPADDING",  (-1,0),(-1,-1), 12),
                    ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ]))
                keep.append(ht)

                if f_owasp:
                    keep.append(Spacer(1, 1*mm))
                    keep.append(_rl_para(f"OWASP: {f_owasp}", ParagraphStyle("owasp_lbl", fontSize=9, fontName="Helvetica-Bold", textColor=colors.HexColor("#1E40AF"), spaceAfter=3, leading=13), max_chars=120))

                if f_desc:
                    keep.append(Spacer(1, 1*mm))
                    # Plain text already — safe to embed directly
                    keep.append(Paragraph(f_desc[:400], S("body")))

                if f_rem:
                    keep.append(Spacer(1, 1*mm))
                    # FIX: f_rem is already _rl_safe output (plain XML-escaped text)
                    keep.append(Paragraph(f"<b>Remediation:</b> {f_rem[:300]}", S("body")))

                keep.append(Spacer(1, 4*mm))
                story.append(KeepTogether(keep))
        else:
            story.append(Paragraph("No findings recorded.", S("body")))

        # ── Footer ────────────────────────────────────────────────────────────
        story.append(Spacer(1, 1*cm))
        story.append(HRFlowable(width="100%", thickness=1, color=C["line"], spaceAfter=8))
        story.append(Paragraph(
            f"Generated by VAPTForge Enterprise v4.0.0 \u2022 {gen_dt} \u2022 CONFIDENTIAL",
            S("footer")
        ))

        doc.build(story, onFirstPage=page_template, onLaterPages=page_template)

        if pdf_path.exists() and pdf_path.stat().st_size > 512:
            with open(str(pdf_path),"rb") as pf:
                if pf.read(5) == b"%PDF-":
                    logger.info(f"PDF via reportlab: {pdf_path}")
                    return str(pdf_path)
        return None

    # ══════════════════════════════════════════════════════════════════════════
    # CSS
    # ══════════════════════════════════════════════════════════════════════════

    def _css(self) -> str:
        return """<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&family=DM+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0;}
body{font-family:'DM Sans',system-ui,sans-serif;background:#F1F5F9;color:#1E293B;font-size:13.5px;line-height:1.65;-webkit-font-smoothing:antialiased;}
.cover{min-height:100vh;display:flex;flex-direction:column;background:linear-gradient(155deg,#020C1B 0%,#0F2545 45%,#0B1D36 100%);color:white;padding:52px 60px 44px;page-break-after:always;position:relative;overflow:hidden;}
.cover::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse at 75% 25%,rgba(59,130,246,0.12) 0%,transparent 60%),radial-gradient(ellipse at 25% 80%,rgba(99,102,241,0.08) 0%,transparent 50%);pointer-events:none;}
.cover-logo{font-size:12px;font-weight:700;letter-spacing:3px;color:#64748B;text-transform:uppercase;margin-bottom:auto;}
.confidential-tag{display:inline-block;background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.35);color:#FCA5A5;padding:4px 14px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:1.2px;margin-bottom:18px;text-transform:uppercase;}
.cover-h1{font-size:44px;font-weight:800;line-height:1.08;margin-bottom:6px;letter-spacing:-0.5px;}
.cover-sub{color:#94A3B8;font-weight:300;font-size:24px;display:block;margin-top:6px;letter-spacing:-0.2px;}
.cover-meta{margin-top:36px;display:grid;grid-template-columns:1fr 1fr;gap:14px 32px;}
.cover-meta-item label{font-size:9px;color:#475569;text-transform:uppercase;letter-spacing:1.2px;display:block;margin-bottom:3px;font-weight:600;}
.cover-meta-item value{font-size:13px;color:#CBD5E1;font-weight:500;display:block;font-family:'DM Mono',monospace;word-break:break-all;}
.cover-risk-panel{margin-top:36px;display:flex;align-items:center;gap:32px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:14px;padding:20px 28px;backdrop-filter:blur(4px);}
.cover-risk-num{font-size:48px;font-weight:800;font-family:'DM Mono',monospace;line-height:1;}
.cover-risk-denom{font-size:20px;color:#64748B;}
.cover-risk-label{font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:1.2px;margin-top:4px;}
.cover-risk-breakdown{display:flex;gap:20px;flex-wrap:wrap;}
.cover-risk-item{display:flex;flex-direction:column;align-items:center;gap:2px;}
.cbig{font-size:22px;font-weight:800;line-height:1;font-family:'DM Mono',monospace;}
.clab{font-size:9px;text-transform:uppercase;letter-spacing:1px;opacity:.7;}
.cover-footer{margin-top:20px;font-size:10px;color:#334155;letter-spacing:.3px;}
.page{max-width:980px;margin:0 auto;padding:40px 48px 60px;}
.section-header{display:flex;align-items:center;gap:14px;margin:52px 0 20px;padding-bottom:14px;border-bottom:2px solid #E2E8F0;page-break-after:avoid;}
.section-num{width:36px;height:36px;background:linear-gradient(135deg,#1E3A8A,#2563EB);color:white;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:800;flex-shrink:0;letter-spacing:0.5px;font-family:'DM Mono',monospace;}
.section-title{font-size:21px;font-weight:700;color:#0F172A;letter-spacing:-0.3px;}
.exec-box{background:white;border:1px solid #E2E8F0;border-radius:12px;padding:22px 26px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.04);}
.exec-text{color:#475569;line-height:1.85;font-size:14px;}
.risk-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:0 0 20px;}
.risk-card{border-radius:10px;padding:16px 10px;text-align:center;border:1px solid;background:white;}
.risk-card-num{font-size:30px;font-weight:800;line-height:1;font-family:'DM Mono',monospace;}
.risk-card-label{font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-top:3px;font-weight:700;}
.chart-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:16px 0 0;}
.chart-box{background:white;border:1px solid #E2E8F0;border-radius:12px;padding:18px 20px;box-shadow:0 1px 3px rgba(0,0,0,0.04);}
.chart-title{font-size:11px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:.8px;margin-bottom:14px;}
.chart-container{height:210px;position:relative;}
.priority-table{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden;border:1px solid #E2E8F0;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.04);}
.priority-table th{background:#0F172A;color:#CBD5E1;padding:10px 14px;text-align:left;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;}
.priority-table td{padding:9px 14px;border-bottom:1px solid #F1F5F9;font-size:12px;vertical-align:middle;}
.priority-table tr:last-child td{border-bottom:none;}
.priority-table tr:hover td{background:#FAFBFF;}
.owasp-table{width:100%;border-collapse:collapse;background:white;border-radius:12px;overflow:hidden;border:1px solid #E2E8F0;box-shadow:0 1px 3px rgba(0,0,0,0.04);}
.owasp-table th{background:#F8FAFC;padding:10px 14px;text-align:left;font-size:10px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:.7px;border-bottom:1px solid #E2E8F0;}
.owasp-table td{padding:10px 14px;border-bottom:1px solid #F1F5F9;font-size:12.5px;}
.owasp-table tr:last-child td{border-bottom:none;}
.owasp-pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:10px;font-weight:700;margin-right:3px;}
.toc{background:white;border:1px solid #E2E8F0;border-radius:12px;padding:20px 22px;box-shadow:0 1px 3px rgba(0,0,0,0.04);}
.toc-item{display:flex;align-items:center;gap:12px;padding:7px 0;border-bottom:1px solid #F8FAFC;}
.toc-item:last-child{border-bottom:none;}
.toc-num{font-size:10px;color:#94A3B8;font-family:'DM Mono',monospace;min-width:44px;}
.toc-title{flex:1;font-size:12.5px;color:#334155;}
.finding{background:white;border:1px solid #E2E8F0;border-radius:13px;margin-bottom:20px;overflow:hidden;page-break-inside:avoid;box-shadow:0 1px 4px rgba(0,0,0,0.05);}
.finding-header{padding:16px 20px;border-bottom:1px solid #F1F5F9;display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;}
.finding-num{font-size:10px;color:#94A3B8;font-family:'DM Mono',monospace;background:#F8FAFC;padding:2px 7px;border-radius:4px;margin-top:3px;flex-shrink:0;border:1px solid #E2E8F0;}
.finding-title{font-size:16px;font-weight:700;color:#0F172A;flex:1;min-width:200px;letter-spacing:-0.2px;}
.sev-badge{padding:4px 12px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase;letter-spacing:.8px;flex-shrink:0;}
.cvss-badge{padding:3px 9px;border-radius:6px;font-size:10px;font-weight:700;background:#1E40AF;color:white;flex-shrink:0;font-family:'DM Mono',monospace;}
.method-badge{padding:2px 8px;border-radius:4px;font-size:9px;font-weight:800;letter-spacing:.5px;flex-shrink:0;}
.confirmed-badge{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:5px;font-size:9px;font-weight:800;background:rgba(22,163,74,0.10);color:#15803D;border:1px solid rgba(22,163,74,0.28);letter-spacing:.3px;flex-shrink:0;}
.finding-meta{display:grid;grid-template-columns:auto 1fr auto 1fr;gap:6px 14px;padding:10px 20px;background:#FAFAFA;border-bottom:1px solid #F1F5F9;font-size:11.5px;}
.meta-label{color:#475569;font-weight:800;white-space:nowrap;font-size:11px;text-transform:uppercase;letter-spacing:0.3px;}
.meta-val{color:#0F172A;font-family:'DM Mono',monospace;word-break:break-all;font-size:11.5px;font-weight:600;}
.affected-urls{padding:8px 20px;background:#FAFAFA;border-bottom:1px solid #F1F5F9;}
.affected-urls-label{font-size:10px;font-weight:700;color:#64748B;text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;}
.affected-urls-list{display:flex;flex-wrap:wrap;gap:5px;}
.url-pill{font-size:10px;font-family:'DM Mono',monospace;background:#F1F5F9;color:#334155;padding:2px 9px;border-radius:4px;border:1px solid #E2E8F0;}
.finding-body{padding:18px 20px;display:grid;grid-template-columns:1fr 1fr;gap:18px;}
.finding-section h4{font-size:10px;font-weight:800;color:#64748B;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center;gap:6px;}
.finding-section h4::before{content:'';display:inline-block;width:3px;height:11px;background:#3B82F6;border-radius:2px;}
.finding-section p{font-size:13px;color:#475569;line-height:1.75;}
.finding-section.full-width{grid-column:1/-1;}
.impact-box{background:#FFF7ED;border:1px solid #FED7AA;border-radius:8px;padding:12px;}
.impact-box p{color:#92400E;font-size:12.5px;line-height:1.65;}
.fix-box{background:#F0FDF4;border:1px solid #BBF7D0;border-radius:8px;padding:12px;}
.fix-box p{color:#166534;font-size:12.5px;line-height:1.65;}
.evidence-box{background:#0D1117;border:1px solid #21262D;border-radius:8px;padding:12px 14px;font-family:'DM Mono',monospace;font-size:11px;color:#C9D1D9;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:160px;overflow-y:auto;line-height:1.6;}
.http-evidence-wrap{margin-top:4px;}
.ev-toggle{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:5px;font-size:10px;font-weight:700;background:#F8FAFC;border:1px solid #E2E8F0;color:#475569;cursor:pointer;font-family:'DM Sans',sans-serif;margin-bottom:8px;}
.ev-toggle:hover{background:#F1F5F9;}
.ev-body{display:none;}
.http-card{border:1px solid #21262D;border-radius:8px;overflow:hidden;margin-bottom:8px;}
.http-card-head{background:#161B22;padding:6px 12px;display:flex;align-items:center;gap:10px;}
.http-card-label{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:1px;}
.http-card-label.req{color:#F59E0B;}
.http-card-label.res{color:#34D399;}
.http-card-meta{font-size:9px;color:#6B7280;font-family:'DM Mono',monospace;}
.http-card-body{background:#0D1117;padding:10px 12px;font-family:'DM Mono',monospace;font-size:10.5px;color:#C9D1D9;white-space:pre-wrap;word-break:break-all;max-height:220px;overflow-y:auto;line-height:1.65;}
.http-method{color:#F59E0B;font-weight:700;}
.http-status-ok{color:#34D399;}
.http-status-err{color:#F87171;}
.http-header-key{color:#79C0FF;}
.http-header-val{color:#A5D6FF;}
.cvss-block{background:#F0F9FF;border:1px solid #BAE6FD;border-radius:8px;padding:10px 12px;margin-top:8px;}
.cvss-score-big{font-size:26px;font-weight:800;font-family:'DM Mono',monospace;}
.cvss-vector{font-size:9.5px;color:#475569;font-family:'DM Mono',monospace;word-break:break-all;margin-top:3px;}
.refs{display:flex;flex-wrap:wrap;gap:5px;}
.ref-link{color:#2563EB;font-size:11.5px;text-decoration:none;background:#EFF6FF;padding:3px 9px;border-radius:5px;border:1px solid #BFDBFE;}
.ref-link:hover{background:#DBEAFE;}
.report-footer{margin-top:48px;padding-top:14px;border-top:1px solid #E2E8F0;display:flex;align-items:center;gap:12px;font-size:11px;color:#94A3B8;}
@media print {
  @page{size:A4 portrait;margin:18mm 16mm 22mm 16mm;}
  @page :first{margin:0;}
  body{background:white;font-size:11px;}
  .cover{page-break-after:always;min-height:0;height:297mm;padding:40mm 20mm 20mm;print-color-adjust:exact;-webkit-print-color-adjust:exact;}
  .page{padding:0;max-width:100%;}
  .section-header{margin:28px 0 14px;page-break-after:avoid;}
  .finding{page-break-inside:avoid;margin-bottom:14px;box-shadow:none;}
  .finding-header{padding:12px 16px;}
  .finding-body{padding:12px 16px;gap:12px;}
  .ev-body{display:block !important;}
  .ev-toggle{display:none !important;}
  .http-card-body{max-height:none;overflow:visible;}
  .evidence-box{max-height:none;overflow:visible;}
  .report-footer{display:none;}
  .section-num,.sev-badge,.cvss-badge,.method-badge,.confirmed-badge,.priority-table th,.cover,.cover-risk-panel,.impact-box,.fix-box,.cvss-block,.http-card-head,.http-card-body,.evidence-box{print-color-adjust:exact;-webkit-print-color-adjust:exact;}
  a{color:inherit !important;text-decoration:none !important;}
}
</style>"""

    # ══════════════════════════════════════════════════════════════════════════
    # Internal helpers
    # ══════════════════════════════════════════════════════════════════════════

    def _executive_summary(self, scan_data: dict, findings: list) -> dict:
        counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in findings:
            sev = _sv(f)
            counts[sev] = counts.get(sev,0)+1
        total = sum(counts.values())
        risk  = scan_data.get("risk_score",0) or 0
        target= scan_data.get("target_url","the target")
        if risk>=7 or counts["critical"]>0:
            rating  = "CRITICAL"
            summary = (
                f"The vulnerability assessment of <strong>{target}</strong> has identified "
                f"<strong>CRITICAL</strong> security exposures requiring immediate remediation. "
                f"{counts['critical']} critical and {counts['high']} high severity issues present "
                f"a substantial risk to data confidentiality, system integrity, and service availability. "
                f"Exploitation of the identified critical vulnerabilities may result in full system compromise "
                f"or exfiltration of sensitive data. Immediate action is strongly recommended."
            )
        elif risk>=4 or counts["high"]>0:
            rating  = "HIGH"
            summary = (
                f"The assessment of <strong>{target}</strong> identified <strong>HIGH</strong> risk "
                f"vulnerabilities. {counts['high']} high-severity issues require prompt remediation "
                f"to reduce the organization's security exposure. A structured remediation plan "
                f"should be initiated within two weeks."
            )
        elif total>0:
            rating  = "MEDIUM"
            summary = (
                f"The assessment of <strong>{target}</strong> identified {total} security findings "
                f"across {len([c for c in counts.values() if c>0])} severity levels. "
                f"A structured remediation plan should be developed and executed per the priority matrix."
            )
        else:
            rating  = "LOW"
            summary = (
                f"The assessment of <strong>{target}</strong> completed without identifying significant "
                f"exploitable vulnerabilities. Ongoing monitoring and periodic reassessment is recommended."
            )
        return {**counts,"total":total,"rating":rating,"executive_text":summary}

    def _owasp_summary(self, findings: list) -> dict:
        OWASP_NAMES = {
            "A01":"Broken Access Control","A02":"Cryptographic Failures",
            "A03":"Injection","A04":"Insecure Design",
            "A05":"Security Misconfiguration","A06":"Vulnerable & Outdated Components",
            "A07":"Identification & Authentication Failures",
            "A08":"Software & Data Integrity Failures",
            "A09":"Security Logging & Monitoring Failures",
            "A10":"Server-Side Request Forgery",
        }
        result = {}
        for cat, name in OWASP_NAMES.items():
            cat_findings = [f for f in findings if _g(f,"owasp_category","").startswith(cat)]
            sevs = {}
            for f in cat_findings:
                s = _sv(f)
                sevs[s] = sevs.get(s,0)+1
            result[cat] = {
                "name": name, "count": len(cat_findings), "severities": sevs,
                "highest": min((_SEV_RANK.get(_sv(f),5) for f in cat_findings),default=5) if cat_findings else None
            }
        return result

    def _risk_matrix(self, findings: list) -> dict:
        matrix = {}
        for f in findings:
            key = (_g(f,"owasp_category",""), _sv(f))
            matrix[str(key)] = matrix.get(str(key),0)+1
        return matrix

    def _finding_dict(self, f) -> dict:
        ev = _g(f,"evidence",{})
        if isinstance(ev,str):
            try: ev = json.loads(ev)
            except: ev = {"raw":ev}
        refs = _g(f,"references",[])
        if isinstance(refs,str):
            try: refs = json.loads(refs)
            except: refs = []
        return {
            "id": _g(f,"id",""), "owasp_category": _g(f,"owasp_category",""),
            "owasp_name": _g(f,"owasp_name",""), "title": _g(f,"title",""),
            "description": _g(f,"description",""), "severity": _sv(f),
            "cvss_score": _g(f,"cvss_score",None), "affected_url": _g(f,"affected_url",""),
            "affected_urls": f.get("_affected_urls",[]) if isinstance(f,dict) else [],
            "affected_parameter": _g(f,"affected_parameter",""),
            "http_method": _g(f,"http_method","GET"), "risk_score": _g(f,"risk_score",0),
            "confidence": _g(f,"confidence",0), "evidence": ev,
            "remediation": _g(f,"remediation",""), "references": refs,
            "detection_methods": f.get("_detection_methods",["DAST"]) if isinstance(f,dict) else ["DAST"],
        }

    def _method_badges_html(self, f) -> str:
        methods      = f.get("_detection_methods",["DAST"]) if isinstance(f,dict) else ["DAST"]
        is_confirmed = "SAST" in methods and "DAST" in methods
        if is_confirmed:
            return '<span class="confirmed-badge">✓ CONFIRMED BY SAST + DAST</span>'
        badges = []
        for m in methods:
            if m == "SAST":
                badges.append('<span class="method-badge" style="background:rgba(168,85,247,0.1);color:#9333EA;border:1px solid rgba(168,85,247,0.28);">SAST</span>')
            else:
                badges.append('<span class="method-badge" style="background:rgba(59,130,246,0.1);color:#2563EB;border:1px solid rgba(59,130,246,0.28);">DAST</span>')
        return " ".join(badges)

    def _method_badge_toc(self, f) -> str:
        methods      = f.get("_detection_methods",["DAST"]) if isinstance(f,dict) else ["DAST"]
        is_confirmed = "SAST" in methods and "DAST" in methods
        if is_confirmed:
            return ' <span style="font-size:9px;color:#15803D;font-weight:800;" title="Confirmed by SAST and DAST">✓</span>'
        m = methods[0] if methods else "DAST"
        color = "#9333EA" if m == "SAST" else "#2563EB"
        return f' <span style="font-size:9px;color:{color};font-weight:700;">[{m}]</span>'

    def _render_http_evidence(self, http_ev: dict, finding_id: int) -> str:
        if not http_ev: return ""
        raw_req  = _trim_http(http_ev.get("raw_request",""), max_lines=28)
        raw_res  = _trim_http(http_ev.get("raw_response",""), max_lines=28)
        protocol = http_ev.get("protocol","HTTPS")
        rt_ms    = http_ev.get("response_time_ms","")
        eid      = f"ev-{finding_id}"
        if not raw_req and not raw_res: return ""

        def highlight_http(text: str, is_request: bool) -> str:
            lines = _escape_html(text).split("\n")
            out = []
            for li, line in enumerate(lines):
                if li == 0 and is_request:
                    line = _re.sub(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)(\s)', r'<span class="http-method">\1</span>\2', line)
                elif li == 0 and not is_request:
                    line = _re.sub(r'^(HTTP/\S+\s+)(\d+)(\s*.*)', lambda m: m.group(1)+f'<span class="{"http-status-ok" if m.group(2).startswith("2") else "http-status-err"}">{m.group(2)}</span>'+m.group(3), line)
                elif ":" in line and li < 30:
                    line = _re.sub(r'^([A-Za-z0-9\-]+)(:)(.*)', r'<span class="http-header-key">\1</span>\2<span class="http-header-val">\3</span>', line)
                out.append(line)
            return "\n".join(out)

        meta_str = f"{protocol}" + (f" · {rt_ms}ms" if rt_ms else "")
        req_html = res_html = ""
        if raw_req:
            req_html = f'<div class="http-card"><div class="http-card-head"><span class="http-card-label req">▶ RAW HTTP REQUEST</span><span class="http-card-meta">{_escape_html(meta_str)}</span></div><div class="http-card-body">{highlight_http(raw_req, True)}</div></div>'
        if raw_res:
            res_html = f'<div class="http-card"><div class="http-card-head"><span class="http-card-label res">◀ RAW HTTP RESPONSE</span><span class="http-card-meta">{_escape_html(meta_str)}</span></div><div class="http-card-body">{highlight_http(raw_res, False)}</div></div>'
        return f'<div class="http-evidence-wrap"><button class="ev-toggle" data-target="{eid}">▼ Show Raw HTTP Evidence</button><div class="ev-body" id="{eid}">{req_html}{res_html}</div></div>'

    def _render_finding_block(self, f, num: int) -> str:
        sev   = _sv(f)
        col   = SEV_COLOR.get(sev,"#6B7280")
        bg    = SEV_BG.get(sev,"#F9FAFB")
        bdr   = SEV_BORDER.get(sev,"#E5E7EB")
        title = _g(f,"title","Unnamed Finding")
        desc  = _g(f,"description","No description available.")
        rem   = _g(f,"remediation","Review and apply security best practices.")
        url   = _g(f,"affected_url","")
        param = _g(f,"affected_parameter","")
        owasp = _g(f,"owasp_category","")
        oname = _g(f,"owasp_name","")
        conf  = _g(f,"confidence",0)
        cvss  = _g(f,"cvss_score",None)
        all_urls = f.get("_affected_urls",[]) if isinstance(f,dict) else []
        if url and url not in all_urls:
            all_urls = [url] + [u for u in all_urls if u != url]
        try: conf_pct = f"{float(conf)*100:.0f}%"
        except: conf_pct = "—"
        cvss_str, cvss_rating_str, cvss_col = "—", "—", "#6B7280"
        if cvss:
            try:
                cvss_val = float(cvss)
                rating, cvss_col = _cvss_rating(cvss_val)
                cvss_str = f"{cvss_val:.1f}"; cvss_rating_str = rating
            except: pass
        ev = _g(f,"evidence",{})
        if isinstance(ev,str):
            try: ev = json.loads(ev)
            except: ev = {"raw":ev}
        all_ev = f.get("_all_evidence",[]) if isinstance(f,dict) else []
        if ev and ev not in all_ev: all_ev = [ev] + all_ev
        http_ev = {}
        for e_item in all_ev:
            if isinstance(e_item, dict) and "http_evidence" in e_item:
                http_ev = e_item["http_evidence"]; break
        if not http_ev and isinstance(ev, dict): http_ev = ev.get("http_evidence", {})
        cvss_vector = ev.get("cvss_vector","") if isinstance(ev,dict) else ""
        ev_display = {k:v for k,v in ev.items() if k not in ("http_evidence","cvss_vector","cvss_score")} if isinstance(ev, dict) else {}
        ev_html = ""
        if ev_display:
            ev_html = "<br>".join(f"<span style='color:#79C0FF;'>{_escape_html(str(k))}</span>: <span style='color:#C9D1D9;'>{_escape_html(str(v)[:300])}</span>" for k,v in list(ev_display.items())[:6])
        refs = _g(f,"references",[])
        if isinstance(refs,str):
            try: refs = json.loads(refs)
            except: refs = [refs] if refs else []
        refs_html = " ".join(f'<a class="ref-link" href="{_escape_html(r)}" target="_blank">{_escape_html(r[:50])}{"…" if len(r)>50 else ""}</a>' for r in refs[:4]) if refs else '<span style="color:#94A3B8;font-size:12px;font-style:italic;">Currently not available</span>'
        cvss_block = ""
        if cvss_str != "—":
            vector_html = f'<div class="cvss-vector">{_escape_html(cvss_vector)}</div>' if cvss_vector else ""
            cvss_block = (
                f'<div class="cvss-block">'
                f'<div style="display:flex;align-items:center;gap:14px;">'
                f'<div><div class="cvss-score-big" style="color:{cvss_col};">{cvss_str}</div>'
                f'<div style="font-size:9.5px;color:#64748B;margin-top:2px;">CVSS v3.1 Score</div></div>'
                f'<div><div style="font-size:13px;font-weight:800;color:{cvss_col};">{cvss_rating_str}</div>'
                f'<div style="font-size:9.5px;color:#64748B;">Rating</div></div>'
                f'</div>{vector_html}</div>'
            )
        method_badges = self._method_badges_html(f)
        urls_block = ""
        if len(all_urls) > 1:
            pills = "".join(f'<span class="url-pill">{_escape_html(u[:80])}</span>' for u in all_urls[:12])
            urls_block = f'<div class="affected-urls"><div class="affected-urls-label">Affected Endpoints ({len(all_urls)})</div><div class="affected-urls-list">{pills}</div></div>'
        primary_url = all_urls[0] if all_urls else url
        show_url_in_meta = len(all_urls) <= 1
        http_ev_html = self._render_http_evidence(http_ev, num)
        return f"""<div class="finding" id="finding-{num}">
  <div class="finding-header">
    <span class="finding-num">#{num:03d}</span>
    <span class="finding-title">{_escape_html(title)}</span>
    {method_badges}
    <span class="sev-badge" style="background:{bg};color:{col};border:1px solid {bdr};">{sev.upper()}</span>
    {f'<span class="cvss-badge">CVSS {cvss_str}</span>' if cvss_str != "—" else ""}
  </div>
  <div class="finding-meta">
    <span class="meta-label">OWASP</span>
    <span style="grid-column:span 3;display:inline-flex;align-items:center;gap:8px;"><span style="background:#1E40AF;color:white;font-family:'DM Mono',monospace;font-size:11px;font-weight:800;padding:2px 9px;border-radius:5px;letter-spacing:0.5px;">{_escape_html(owasp)}</span><span style="color:#1E293B;font-size:12px;font-weight:600;">{_escape_html(oname)}</span></span>
    {f'<span class="meta-label">Affected URL</span><span class="meta-val" style="grid-column:span 3;">{_escape_html(primary_url[:120])}</span>' if show_url_in_meta and primary_url else ""}
    {f'<span class="meta-label">Parameter</span><span class="meta-val">{_escape_html(param)}</span>' if param else ""}
    <span class="meta-label">Confidence</span><span class="meta-val">{conf_pct}</span>
  </div>
  {urls_block}
  <div class="finding-body">
    <div class="finding-section"><h4>Description</h4><p>{_escape_html(desc[:900])}</p></div>
    <div class="finding-section"><h4>Impact</h4><div class="impact-box"><p>{self._impact_text(sev, oname)}</p></div>{cvss_block}</div>
    <div class="finding-section full-width"><h4>Remediation</h4><div class="fix-box"><p>{_escape_html(rem[:700] or "Follow OWASP remediation guidance for "+oname+".")}</p></div></div>
    {f'<div class="finding-section full-width"><h4>Detection Evidence</h4><div class="evidence-box">{ev_html}</div></div>' if ev_html else ""}
    {f'<div class="finding-section full-width"><h4>Raw HTTP Evidence</h4>{http_ev_html}</div>' if http_ev_html else ""}
    <div class="finding-section full-width"><h4>References</h4><div class="refs">{refs_html}</div></div>
  </div>
</div>"""

    def _impact_text(self, sev: str, oname: str) -> str:
        impacts = {
            "critical": "Immediate exploitation is possible without requiring complex attack chains. Successful exploitation may allow full system compromise, mass data exfiltration, ransomware deployment, or complete service disruption. Emergency remediation is required.",
            "high":     "Significant security risk with a realistic exploitation path. Successful exploitation could lead to unauthorized access, sensitive data exposure, or privilege escalation. Remediation within 1-2 weeks is strongly recommended.",
            "medium":   "Moderate risk. Exploitation requires specific conditions, user interaction, or multiple steps, but could lead to information disclosure, partial unauthorized access, or facilitation of more severe attacks.",
            "low":      "Limited direct impact. Low likelihood of active exploitation but contributes to attack surface or aids adversary reconnaissance. Address during next planned maintenance cycle.",
            "info":     "Informational finding with no direct exploitability. May assist attackers in reconnaissance or lateral movement if combined with other vulnerabilities.",
        }
        return impacts.get(sev, "Review and remediate per your organization's security policy.")

    def _render_priority_matrix(self, findings: list) -> str:
        rows = ""
        for i, f in enumerate(findings[:25]):
            sev      = _sv(f); col = SEV_COLOR.get(sev,"#6B7280"); bg = SEV_BG.get(sev,"#F9FAFB"); bdr = SEV_BORDER.get(sev,"#E5E7EB")
            title    = _g(f,"title","")[:60]; owasp = _g(f,"owasp_category",""); cvss = _g(f,"cvss_score",None)
            priority = _SEV_RANK.get(sev,4)+1
            timeline = {"critical":"Immediate (24-48h)","high":"Short-term (1-2 weeks)","medium":"Medium-term (1 month)","low":"Long-term (3 months)","info":"Best effort"}.get(sev,"As needed")
            cvss_str = f"{float(cvss):.1f}" if cvss else "—"
            all_urls = f.get("_affected_urls",[]) if isinstance(f,dict) else []
            ep_str   = f"{len(all_urls)} endpoint{'s' if len(all_urls)!=1 else ''}" if all_urls else "—"
            _dm = "DM Mono"
            rows += (
                f'<tr>'
                f'<td style="font-weight:800;color:{col};font-family:{_dm},monospace;">P{priority}</td>'
                f'<td><span style="font-weight:600;color:#1E293B;">{_escape_html(title)}</span>'
                f'<span style="margin-left:6px;">{self._method_badges_html(f)}</span></td>'
                f'<td><span style="background:{bg};color:{col};border:1px solid {bdr};padding:2px 9px;border-radius:5px;font-size:10px;font-weight:800;">{sev.upper()}</span></td>'
                f'<td><span style="font-family:{_dm},monospace;font-size:10.5px;font-weight:800;background:#EFF6FF;color:#1E40AF;padding:2px 8px;border-radius:4px;border:1px solid #BFDBFE;">{_escape_html(owasp)}</span></td>'
                f'<td style="font-family:{_dm},monospace;font-size:11px;color:#1E40AF;font-weight:700;">{cvss_str}</td>'
                f'<td style="font-size:11px;color:#64748B;">{ep_str}</td>'
                f'<td style="font-size:11px;color:#475569;">{timeline}</td>'
                f'</tr>'
            )
        return f'<table class="priority-table"><thead><tr><th>Priority</th><th>Finding</th><th>Severity</th><th>OWASP</th><th>CVSS v3</th><th>Endpoints</th><th>Timeline</th></tr></thead><tbody>{rows}</tbody></table>'

    def _render_owasp_table(self, owasp: dict) -> str:
        rows = ""
        for cat, data in owasp.items():
            count = data.get("count",0); name = data.get("name",""); sevs = data.get("severities",{})
            sev_pills = " ".join(f'<span class="owasp-pill" style="background:{SEV_BG.get(s,"#F9FAFB")};color:{SEV_COLOR.get(s,"#6B7280")};border:1px solid {SEV_BORDER.get(s,"#E5E7EB")};">{n}×{s}</span>' for s,n in sevs.items())
            status_color = "#DC2626" if count>0 else "#22C55E"
            _empty_pill = '<span style="color:#94A3B8;">—</span>'
            rows += (
                f'<tr>'
                f'<td><b style="font-family:DM Mono,monospace;">{cat}</b></td>'
                f'<td>{_escape_html(name)}</td>'
                f'<td style="text-align:center;"><span style="color:{status_color};font-weight:800;font-family:DM Mono,monospace;">{count}</span></td>'
                f'<td>{sev_pills if sev_pills else _empty_pill}</td>'
                f'</tr>'
            )
        return f'<table class="owasp-table"><thead><tr><th>Category</th><th>Name</th><th style="text-align:center;">Findings</th><th>Severity Breakdown</th></tr></thead><tbody>{rows}</tbody></table>'

    def _render_toc(self, findings: list) -> str:
        if not findings: return "<p style='color:#94A3B8;font-size:13px;'>No findings.</p>"
        items = ""
        for i, f in enumerate(findings[:100]):
            sev = _sv(f); col = SEV_COLOR.get(sev,"#6B7280"); bg = SEV_BG.get(sev,"#F9FAFB"); bdr = SEV_BORDER.get(sev,"#E5E7EB")
            title = _g(f,"title","Unnamed Finding"); owasp = _g(f,"owasp_category",""); cvss = _g(f,"cvss_score",None)
            cvss_str = f" · CVSS {float(cvss):.1f}" if cvss else ""
            all_urls = f.get("_affected_urls",[]) if isinstance(f,dict) else []
            ep_tag = f' <span style="font-size:9px;color:#94A3B8;">[{len(all_urls)} endpoints]</span>' if len(all_urls)>1 else ""
            _dm = "DM Mono"
            items += (
                f'<div class="toc-item">'
                f'<span class="toc-num">#{i+1:03d}</span>'
                f'<a href="#finding-{i+1}" style="text-decoration:none;flex:1;">'
                f'<span class="toc-title">{_escape_html(title[:65])}{self._method_badge_toc(f)}{ep_tag}</span></a>'
                f'<span style="font-size:10.5px;color:{col};font-weight:700;padding:2px 9px;background:{bg};border:1px solid {bdr};border-radius:5px;">{sev.upper()}{cvss_str}</span>'
                f'<span style="font-size:10px;color:#1E40AF;font-weight:800;margin-left:8px;font-family:{_dm},monospace;background:#EFF6FF;padding:1px 7px;border-radius:4px;border:1px solid #BFDBFE;">{_escape_html(owasp)}</span>'
                f'</div>'
            )
        return items

    def _render_sev_chart(self, crit, high, med, low, info_) -> str:
        import math
        data = [(int(crit or 0),"#DC2626","Critical"),(int(high or 0),"#EA580C","High"),(int(med or 0),"#D97706","Medium"),(int(low or 0),"#2563EB","Low"),(int(info_ or 0),"#94A3B8","Info")]
        total = sum(d[0] for d in data)
        if total == 0: return '<div style="display:flex;align-items:center;justify-content:center;height:180px;color:#94A3B8;font-size:13px;">No findings</div>'
        cx,cy,r_out,r_in = 88,95,72,38; angle = -math.pi/2; segments = []
        for count, color, label in data:
            if count == 0: continue
            sweep = (count/total)*2*math.pi
            x1=cx+r_out*math.cos(angle); y1=cy+r_out*math.sin(angle)
            x2=cx+r_out*math.cos(angle+sweep); y2=cy+r_out*math.sin(angle+sweep)
            ix1=cx+r_in*math.cos(angle+sweep); iy1=cy+r_in*math.sin(angle+sweep)
            ix2=cx+r_in*math.cos(angle); iy2=cy+r_in*math.sin(angle)
            large = 1 if sweep > math.pi else 0
            segments.append(f'<path d="M {x1:.1f} {y1:.1f} A {r_out} {r_out} 0 {large} 1 {x2:.1f} {y2:.1f} L {ix1:.1f} {iy1:.1f} A {r_in} {r_in} 0 {large} 0 {ix2:.1f} {iy2:.1f} Z" fill="{color}" stroke="white" stroke-width="2.5"/>'); angle += sweep
        legend = ""; ly = 22
        for count, color, label in data:
            if count == 0: continue
            legend += f'<rect x="182" y="{ly}" width="11" height="11" rx="3" fill="{color}"/><text x="198" y="{ly+9}" font-size="11" fill="#475569" font-family="DM Sans,Arial,sans-serif">{label}: {count}</text>'; ly += 21
        center = f'<text x="{cx}" y="{cy-5}" text-anchor="middle" font-size="24" font-weight="800" fill="#0F172A" font-family="DM Sans,Arial,sans-serif">{total}</text><text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="10" fill="#64748B" font-family="DM Sans,Arial,sans-serif">Total</text>'
        return f'<svg viewBox="0 0 370 190" width="100%" height="190" xmlns="http://www.w3.org/2000/svg">{"".join(segments)}{center}{legend}</svg>'

    def _render_owasp_bar_chart(self, counts: list, labels: list) -> str:
        max_val = max(counts) if counts and max(counts) > 0 else 1
        chart_h=140; bar_w=26; gap=7; lm=28
        bar_colors=["#DC2626","#EA580C","#D97706","#6B7280","#3B82F6","#8B5CF6","#EC4899","#14B8A6","#F59E0B","#10B981"]
        bars=x_labels=y_labels=""
        for i,(count,label) in enumerate(zip(counts,labels)):
            bar_h=int((count/max_val)*chart_h) if max_val>0 else 0; x=lm+i*(bar_w+gap); y=chart_h-bar_h+10; color=bar_colors[i%len(bar_colors)]
            bars+=f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_h}" fill="{color}" rx="3" opacity="0.9"/>'
            if count>0: bars+=f'<text x="{x+bar_w//2}" y="{y-4}" text-anchor="middle" font-size="9" fill="#475569" font-family="DM Sans,Arial,sans-serif">{count}</text>'
            x_labels+=f'<text x="{x+bar_w//2}" y="{chart_h+24}" text-anchor="middle" font-size="9" fill="#64748B" font-family="DM Sans,Arial,sans-serif">{label}</text>'
        for v in [0,max_val//2,max_val]:
            if max_val==0: continue
            yp=chart_h-int((v/max_val)*chart_h)+10
            y_labels+=f'<text x="{lm-4}" y="{yp+3}" text-anchor="end" font-size="9" fill="#94A3B8" font-family="DM Sans,Arial,sans-serif">{v}</text><line x1="{lm}" y1="{yp}" x2="{lm+370}" y2="{yp}" stroke="#F1F5F9" stroke-width="1"/>'
        tw=lm+len(labels)*(bar_w+gap)+10; th=chart_h+40
        return f'<svg viewBox="0 0 {tw} {th}" width="100%" height="{th}" xmlns="http://www.w3.org/2000/svg">{y_labels}{bars}{x_labels}<line x1="{lm}" y1="10" x2="{lm}" y2="{chart_h+10}" stroke="#E2E8F0" stroke-width="1"/><line x1="{lm}" y1="{chart_h+10}" x2="{tw-5}" y2="{chart_h+10}" stroke="#E2E8F0" stroke-width="1"/></svg>'


report_generator = ReportGenerator("./reports") 