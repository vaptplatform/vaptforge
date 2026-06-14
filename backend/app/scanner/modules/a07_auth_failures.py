"""
OWASP A07 — Identification and Authentication Failures
Evidence-based: JWT header decode, cookie flag inspection, autocomplete field check.
"""
import re, logging, base64, json as _json
from typing import List
import httpx
from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a07")

JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')


class AuthFailuresModule(BaseModule):
    module_id = "a07_auth_failures"
    owasp_category = "A07"
    owasp_name = "Identification and Authentication Failures"
    severity_weight = 7.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        headers = {k.lower(): v for k, v in ctx.response_headers.items()}
        body    = ctx.response_body

        # 1. JWT algorithm weakness
        jwt_match = JWT_RE.search(body)
        if jwt_match:
            findings.extend(self._analyse_jwt(ctx.url, jwt_match.group(0)))

        # 2. Autocomplete on password fields
        if 'type="password"' in body.lower():
            if 'autocomplete="off"' not in body.lower() and 'autocomplete="new-password"' not in body.lower():
                findings.append(self.build_finding(
                    title="Password Field Allows Autocomplete",
                    description=(
                        f"A password input at {ctx.url} does not have autocomplete='off'. "
                        f"Browsers may cache credentials and expose them to other users on shared devices."
                    ),
                    severity=Severity.LOW,
                    url=ctx.url,
                    evidence={
                        "detection_method": "dom_attribute_check",
                        "condition": "type=password without autocomplete=off",
                    },
                    remediation="Add autocomplete='off' or autocomplete='new-password' to all password fields.",
                    confidence=0.85,
                ))

        # 3. Session cookie flags
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            for flag, title, sev, fix in [
                ("httponly", "Session Cookie Missing HttpOnly Flag", Severity.MEDIUM,
                 "Add HttpOnly to all session cookies."),
                ("secure",   "Session Cookie Missing Secure Flag",   Severity.MEDIUM,
                 "Add Secure flag to all session cookies."),
                ("samesite", "Session Cookie Missing SameSite",      Severity.LOW,
                 "Add SameSite=Strict or Lax to session cookies."),
            ]:
                if flag not in set_cookie.lower():
                    findings.append(self.build_finding(
                        title=title,
                        description=f"Set-Cookie header at {ctx.url} is missing the '{flag}' attribute.",
                        severity=sev,
                        url=ctx.url,
                        evidence={
                            "detection_method": "cookie_flag_check",
                            "set_cookie_header": set_cookie[:200],
                            "missing_flag": flag,
                        },
                        remediation=fix,
                        confidence=0.95,
                    ))

        return findings

    def _analyse_jwt(self, url: str, raw_jwt: str) -> List[RawFinding]:
        results: List[RawFinding] = []
        try:
            header_b64 = raw_jwt.split(".")[0]
            padded = header_b64 + "=" * (4 - len(header_b64) % 4)
            decoded = _json.loads(base64.urlsafe_b64decode(padded))
            alg = decoded.get("alg", "")

            if not alg or alg.lower() == "none":
                results.append(self.build_finding(
                    title="JWT alg:none — Unsigned Token Accepted",
                    description=(
                        f"A JWT token with algorithm 'none' was found at {url}. "
                        f"If the server accepts unsigned tokens, any user can forge arbitrary claims "
                        f"and bypass authentication entirely."
                    ),
                    severity=Severity.CRITICAL,
                    url=url,
                    evidence={
                        "detection_method": "jwt_header_decode",
                        "jwt_algorithm": alg or "none",
                        "jwt_header_decoded": decoded,
                        "raw_snippet": raw_jwt[:80],
                    },
                    remediation=(
                        "Reject JWTs where alg is 'none'. "
                        "Use RS256 or ES256 asymmetric algorithms. "
                        "Validate algorithm on the server side explicitly."
                    ),
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                    confidence=0.93,
                ))
            elif alg.upper() == "HS256":
                results.append(self.build_finding(
                    title="JWT Using Symmetric HS256 Algorithm",
                    description=(
                        f"A JWT using HS256 (HMAC-SHA256) was found at {url}. "
                        f"If the signing secret is weak or reused, the token can be brute-forced offline."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence={
                        "detection_method": "jwt_header_decode",
                        "jwt_algorithm": "HS256",
                        "jwt_header_decoded": decoded,
                    },
                    remediation="Switch to RS256/ES256. Use a 256-bit random secret for HS256 if kept.",
                    confidence=0.70,
                ))
        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")
        return results
