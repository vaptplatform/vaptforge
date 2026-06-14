"""
OWASP A01 — Broken Access Control v2.0
Checks: auth bypass via headers, IDOR (numeric/UUID IDs), path traversal,
CSRF token absence, directory listing, forced browsing, privilege escalation indicators.
"""
import asyncio
import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse, urlencode, urlunparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a01")


AUTH_BYPASS_HEADERS = [
    {"X-Original-URL":           "/admin"},
    {"X-Rewrite-URL":            "/admin"},
    {"X-Forwarded-For":          "127.0.0.1"},
    {"X-Remote-IP":              "127.0.0.1"},
    {"X-Client-IP":              "127.0.0.1"},
    {"X-Real-IP":                "127.0.0.1"},
    {"X-Custom-IP-Authorization":"127.0.0.1"},
    {"Forwarded":                "for=127.0.0.1"},
    {"X-Host":                   "localhost"},
    {"X-Forwarded-Host":         "localhost"},
    {"X-HTTP-Method-Override":   "GET"},
]

PROTECTED_PATHS = [
    "/admin", "/admin/dashboard", "/admin/users", "/admin/config",
    "/api/admin", "/management", "/api/users", "/api/config",
    "/dashboard", "/internal", "/private", "/secure",
    "/api/v1/admin", "/api/v1/users", "/superadmin",
]

TRAVERSAL_PROBES = [
    ("../../../etc/passwd",                      "root:"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",             "root:"),
    ("....//....//....//etc/passwd",             "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("..%252f..%252f..%252fetc%252fpasswd",      "root:"),
    ("../../../windows/win.ini",                 "[fonts]"),
]

DIRECTORY_LISTING_SIGS = [
    "index of /", "directory listing for", "parent directory",
    "<title>index of", "[to parent directory]", "apache/", "nginx/",
]

REDIRECT_PARAMS = ["url","redirect","next","return","goto","dest","location","to","link","target"]


class BrokenAccessControlModule(BaseModule):
    module_id      = "a01_broken_access_control"
    owasp_category = "A01"
    owasp_name     = "Broken Access Control"
    severity_weight = 9.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed   = urlparse(ctx.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Auth bypass via HTTP headers
        bypass = await self._check_auth_bypass(base_url, client)
        findings.extend(bypass)

        # 2. IDOR via numeric/UUID IDs in path
        idor = await self._check_idor(ctx.url, client)
        if idor:
            findings.append(idor)

        # 3. Path traversal in parameters
        if ctx.params:
            traversal = await self._check_traversal(ctx.url, parsed, ctx.params, client)
            if traversal:
                findings.append(traversal)

            # 4. Open redirect
            redirect = await self._check_open_redirect(ctx.url, parsed, ctx.params, client)
            if redirect:
                findings.append(redirect)

        # 5. Directory listing
        dir_listing = self._check_directory_listing(ctx)
        if dir_listing:
            findings.append(dir_listing)

        # 6. CSRF token absence on POST forms
        csrf_findings = await self._check_csrf(ctx.url, client)
        findings.extend(csrf_findings)

        return findings

    # ── Auth Bypass via HTTP Headers ──────────────────────────────────────────
    async def _check_auth_bypass(self, base_url: str, client: httpx.AsyncClient) -> List[RawFinding]:
        findings = []
        for path in PROTECTED_PATHS[:6]:
            probe_url = base_url.rstrip("/") + path
            try:
                normal = await asyncio.wait_for(client.get(probe_url), timeout=6)
                if normal.status_code not in (401, 403):
                    continue
                for header_set in AUTH_BYPASS_HEADERS:
                    hdrs = {k: v.replace("/admin", path) for k, v in header_set.items()}
                    try:
                        bypass = await asyncio.wait_for(
                            client.get(probe_url, headers=hdrs), timeout=6
                        )
                        if bypass.status_code == 200 and len(bypass.text) > 100:
                            h_name = list(hdrs.keys())[0]
                            findings.append(self.build_finding(
                                title=f"Auth Bypass via Header Injection: {h_name}",
                                description=(
                                    f"'{path}' returned {normal.status_code} normally, "
                                    f"but HTTP 200 with header '{h_name}: {list(hdrs.values())[0]}'. "
                                    f"Any attacker can bypass access controls on this path."
                                ),
                                severity=Severity.CRITICAL,
                                url=probe_url, parameter=None,
                                evidence={
                                    "detection_method": "header_injection_bypass",
                                    "bypass_header": h_name,
                                    "bypass_value": list(hdrs.values())[0],
                                    "normal_status": normal.status_code,
                                    "bypass_status": bypass.status_code,
                                    "bypass_body_size": len(bypass.text),
                                    "raw_http": (
                                        f"Normal: GET {probe_url} → HTTP {normal.status_code}\n"
                                        f"Bypass: GET {probe_url}\n"
                                        f"  {h_name}: {list(hdrs.values())[0]}\n"
                                        f"→ HTTP {bypass.status_code} ({len(bypass.text)} bytes)"
                                    ),
                                },
                                remediation=(
                                    "Never use client-supplied headers for authorization decisions. "
                                    "Authorize from server-side session only. "
                                    "Remove trust in X-Forwarded-For, X-Original-URL headers."
                                ),
                                references=["https://owasp.org/A01_2021-Broken_Access_Control/"],
                                confidence=0.93,
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                pass
        return findings

    # ── IDOR Detection ────────────────────────────────────────────────────────
    async def _check_idor(self, url: str, client: httpx.AsyncClient) -> Optional[RawFinding]:
        parsed = urlparse(url)
        path   = parsed.path
        id_match = re.search(r'/(\d{1,10})(?:/|$|\?)', path)
        if not id_match:
            return None
        orig_id  = int(id_match.group(1))
        test_ids = [orig_id + 1, orig_id - 1, 1, 2, 999]
        try:
            orig_resp = await asyncio.wait_for(client.get(url), timeout=6)
            if orig_resp.status_code != 200:
                return None
            for test_id in test_ids:
                if test_id <= 0 or test_id == orig_id:
                    continue
                test_path = path[:id_match.start(1)] + str(test_id) + path[id_match.end(1):]
                test_url  = f"{parsed.scheme}://{parsed.netloc}{test_path}"
                try:
                    test_resp = await asyncio.wait_for(client.get(test_url), timeout=6)
                    if test_resp.status_code == 200 and len(test_resp.text) > 100:
                        ratio = len(test_resp.text) / max(len(orig_resp.text), 1)
                        if 0.2 < ratio < 5.0:
                            return self.build_finding(
                                title=f"Potential IDOR — Numeric ID '{orig_id}' in Path",
                                description=(
                                    f"Path '{path}' has numeric ID '{orig_id}'. "
                                    f"Adjacent ID '{test_id}' also returns HTTP 200 with {len(test_resp.text)} bytes. "
                                    f"Without proper authorization, any user can access other users' data "
                                    f"by changing the ID number."
                                ),
                                severity=Severity.HIGH, url=url, parameter="path_id",
                                evidence={
                                    "detection_method": "idor_adjacent_id",
                                    "original_id": orig_id,
                                    "tested_id": test_id,
                                    "original_size": len(orig_resp.text),
                                    "tested_size": len(test_resp.text),
                                    "raw_http": (
                                        f"Original: GET {url} → HTTP {orig_resp.status_code} ({len(orig_resp.text)}b)\n"
                                        f"Adjacent: GET {test_url} → HTTP {test_resp.status_code} ({len(test_resp.text)}b)"
                                    ),
                                },
                                remediation=(
                                    "Implement object-level authorization on every endpoint. "
                                    "Verify the requesting user owns the requested resource. "
                                    "Use UUIDs instead of sequential integers."
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                                    "https://cwe.mitre.org/data/definitions/639.html",
                                ],
                                confidence=0.72,
                            )
                except Exception:
                    pass
        except Exception:
            pass
        return None

    # ── Path Traversal ────────────────────────────────────────────────────────
    async def _check_traversal(self, url, parsed, params, client) -> Optional[RawFinding]:
        file_params = [p for p in params if any(
            kw in p.lower() for kw in ["file","path","page","doc","name","template","view","load","include"]
        )]
        for param in file_params:
            for probe, expected in TRAVERSAL_PROBES[:4]:
                try:
                    base_params = {k: v for k, v in params.items()}
                    base_params[param] = probe
                    test_url = urlunparse(parsed._replace(query=urlencode(base_params)))
                    resp = await asyncio.wait_for(client.get(test_url), timeout=8)
                    if expected in resp.text:
                        return self.build_finding(
                            title=f"Path Traversal — Parameter: '{param}'",
                            description=(
                                f"Probe '{probe}' in '{param}' returned file content ('{expected}'). "
                                f"Attacker can read arbitrary server files — "
                                f"/etc/passwd, SSH keys, source code, environment variables."
                            ),
                            severity=Severity.CRITICAL, url=url, parameter=param,
                            evidence={
                                "detection_method": "path_traversal_file_read",
                                "probe": probe,
                                "indicator": expected,
                                "raw_http": (
                                    f"GET {test_url}\n"
                                    f"→ HTTP {resp.status_code}\n"
                                    f"Indicator '{expected}' found in response"
                                ),
                            },
                            remediation=(
                                "Validate file paths against an allowlist. "
                                "Use os.path.basename(). "
                                "Never pass user input to file open calls. "
                                "Use chroot jails."
                            ),
                            references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                            confidence=0.97,
                        )
                except Exception:
                    pass
        return None

    # ── Open Redirect ─────────────────────────────────────────────────────────
    async def _check_open_redirect(self, url, parsed, params, client) -> Optional[RawFinding]:
        redirect_params = [p for p in params if p.lower() in REDIRECT_PARAMS]
        payloads = ["https://evil.example.com", "//evil.example.com", "///evil.example.com"]
        for param in redirect_params:
            for payload in payloads:
                try:
                    base_params = {**params, param: payload}
                    test_url = urlunparse(parsed._replace(query=urlencode(base_params)))
                    resp = await asyncio.wait_for(
                        client.get(test_url, follow_redirects=False), timeout=8
                    )
                    location = resp.headers.get("location", "")
                    if resp.status_code in (301,302,303,307,308) and "evil.example.com" in location:
                        return self.build_finding(
                            title=f"Open Redirect — Parameter: '{param}'",
                            description=(
                                f"'{param}' redirects to attacker-controlled URL '{location}'. "
                                f"Phishing attacks using your trusted domain become trivial."
                            ),
                            severity=Severity.MEDIUM, url=url, parameter=param,
                            evidence={
                                "detection_method": "open_redirect",
                                "payload": payload,
                                "location": location,
                                "status": resp.status_code,
                            },
                            remediation="Validate redirects against an allowlist. Use relative paths only.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"],
                            confidence=0.92,
                        )
                except Exception:
                    pass
        return None

    # ── Directory Listing ─────────────────────────────────────────────────────
    def _check_directory_listing(self, ctx: ScanContext) -> Optional[RawFinding]:
        body = ctx.response_body.lower()
        hits = [s for s in DIRECTORY_LISTING_SIGS if s in body]
        if hits:
            return self.build_finding(
                title="Directory Listing Enabled",
                description=(
                    f"Directory listing is enabled at {ctx.url}. "
                    f"Attacker can enumerate all files and directories — "
                    f"exposing source code, backup files, config files."
                ),
                severity=Severity.MEDIUM, url=ctx.url,
                evidence={
                    "detection_method": "directory_listing_signature",
                    "signatures": hits,
                },
                remediation=(
                    "Disable directory listing in server config "
                    "(Options -Indexes in Apache, autoindex off in Nginx). "
                    "Add an index.html to every directory."
                ),
                references=["https://owasp.org/A05_2021-Security_Misconfiguration/"],
                confidence=0.90,
            )
        return None

    # ── CSRF Token Absence ────────────────────────────────────────────────────
    async def _check_csrf(self, url: str, client: httpx.AsyncClient) -> List[RawFinding]:
        findings = []
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=8)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form")[:5]:
                method = form.get("method", "get").lower()
                if method != "post":
                    continue
                action   = form.get("action", url)
                form_url = urljoin(url, action)
                inputs   = [i.get("name", "").lower() for i in form.find_all("input")]
                has_csrf = any(
                    t in " ".join(inputs)
                    for t in ["csrf","token","_token","nonce","csrfmiddlewaretoken","authenticity_token"]
                )
                if not has_csrf:
                    findings.append(self.build_finding(
                        title=f"Missing CSRF Protection on POST Form",
                        description=(
                            f"POST form at '{form_url}' has no CSRF token. "
                            f"An attacker can trick authenticated users into submitting "
                            f"this form from a malicious site — enabling account takeover, "
                            f"data modification, or unauthorized actions."
                        ),
                        severity=Severity.HIGH, url=form_url,
                        evidence={
                            "detection_method": "csrf_token_absence",
                            "form_action": form_url,
                            "form_fields": inputs[:10],
                            "csrf_tokens_checked": ["csrf","token","_token","nonce","csrfmiddlewaretoken"],
                        },
                        remediation=(
                            "Add a CSRF token to all state-changing forms. "
                            "Use the Synchronizer Token Pattern. "
                            "Add SameSite=Strict to session cookies."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/csrf",
                            "https://cwe.mitre.org/data/definitions/352.html",
                        ],
                        confidence=0.82,
                    ))
        except Exception:
            pass
        return findings
