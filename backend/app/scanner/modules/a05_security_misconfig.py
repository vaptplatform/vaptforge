"""
OWASP A05 — Security Misconfiguration
Evidence-based: header presence checks, error disclosure in body, directory listing detection.
"""
import re
import logging
from typing import List
import httpx
from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a05")

SECURITY_HEADERS = [
    ("content-security-policy",  "Missing Content-Security-Policy (CSP)",     Severity.MEDIUM,
     "Add CSP: Content-Security-Policy: default-src 'self'; script-src 'self'"),
    ("x-content-type-options",   "Missing X-Content-Type-Options",             Severity.LOW,
     "Add: X-Content-Type-Options: nosniff"),
    ("x-frame-options",          "Missing X-Frame-Options (Clickjacking Risk)", Severity.MEDIUM,
     "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)"),
    ("referrer-policy",          "Missing Referrer-Policy",                    Severity.LOW,
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy",       "Missing Permissions-Policy",                 Severity.LOW,
     "Add Permissions-Policy to disable unneeded browser APIs"),
]

SERVER_VERSION_RE = re.compile(
    r"(Apache/[\d.]+|nginx/[\d.]+|Microsoft-IIS/[\d.]+|PHP/[\d.]+|"
    r"Express|Django/[\d.]+|Rails/[\d.]+|Tomcat/[\d.]+)",
    re.I,
)


class SecurityMisconfigModule(BaseModule):
    module_id = "a05_security_misconfig"
    owasp_category = "A05"
    owasp_name = "Security Misconfiguration"
    severity_weight = 5.5

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # 1. Verbose error / stack trace disclosure in body
        error_sig = self.check_error_disclosure(ctx.response_body)
        if error_sig:
            findings.append(self.build_finding(
                title="Verbose Error / Stack Trace Disclosure",
                description=(
                    f"The response at {ctx.url} contains a verbose error message or stack trace. "
                    f"This reveals implementation details (file paths, class names, framework versions) "
                    f"that significantly aid attackers in crafting targeted exploits."
                ),
                severity=Severity.MEDIUM,
                url=ctx.url,
                evidence={
                    "detection_method": "error_pattern_match",
                    "error_snippet": error_sig[:300],
                    "response_status": ctx.status_code,
                },
                remediation=(
                    "Disable debug/verbose mode in production. "
                    "Use generic error pages for end users. "
                    "Log detailed errors server-side only."
                ),
                confidence=0.91,
            ))

        # 2. Directory listing
        if ctx.status_code == 200 and (
            "Index of /" in ctx.response_body or "Directory Listing" in ctx.response_body
        ):
            findings.append(self.build_finding(
                title="Directory Listing Enabled",
                description=(
                    f"The web server exposes a directory listing at {ctx.url}, "
                    f"revealing the file and folder structure. Sensitive files may be directly accessible."
                ),
                severity=Severity.MEDIUM,
                url=ctx.url,
                evidence={
                    "detection_method": "directory_listing_pattern",
                    "indicator": "Index of / or Directory Listing in body",
                    "response_status": ctx.status_code,
                    "snippet": ctx.response_body[:200],
                },
                remediation=(
                    "Disable directory listing: 'Options -Indexes' (Apache) or 'autoindex off' (Nginx)."
                ),
                confidence=0.95,
            ))

        return findings

    async def analyze_headers(self, ctx: ScanContext) -> List[RawFinding]:
        findings: List[RawFinding] = []
        headers = {k.lower(): v for k, v in ctx.response_headers.items()}

        # Security header presence checks
        for header, title, severity, fix in SECURITY_HEADERS:
            if header not in headers:
                findings.append(self.build_finding(
                    title=title,
                    description=(
                        f"The response from {ctx.url} is missing the '{header}' security header. "
                        f"This reduces browser-level protection against common attack classes."
                    ),
                    severity=severity,
                    url=ctx.url,
                    evidence={
                        "detection_method": "header_presence_check",
                        "missing_header": header,
                        "headers_present": [h for h in headers if h.startswith("x-") or h in ("content-security-policy", "strict-transport-security")],
                    },
                    remediation=fix,
                    confidence=0.99,
                ))

        # Server / X-Powered-By version disclosure
        for hdr in ["server", "x-powered-by"]:
            val = headers.get(hdr, "")
            match = SERVER_VERSION_RE.search(val)
            if match:
                findings.append(self.build_finding(
                    title=f"Server Technology Version Disclosed: {match.group(0)}",
                    description=(
                        f"The '{hdr}' header reveals the server technology and version: '{val}'. "
                        f"Attackers can use this to target known CVEs for that specific version."
                    ),
                    severity=Severity.LOW,
                    url=ctx.url,
                    evidence={
                        "detection_method": "header_value_pattern",
                        "header": hdr,
                        "value": val,
                        "version_match": match.group(0),
                    },
                    remediation=f"Remove or generalise the '{hdr}' header in server configuration.",
                    confidence=0.96,
                ))
        return findings
