"""
VAPTForge DOM Scanner — Headless Browser Security Testing
Uses Playwright (if available) for real JavaScript execution.
Falls back to static analysis if Playwright not installed.

Detects:
- DOM XSS (real JS execution, not just pattern matching)
- Client-side prototype pollution
- Sensitive data in JS variables / localStorage
- Postmessage vulnerabilities
- Open redirects via JS (window.location manipulation)
- Clickjacking (iframe embedding test)
- Mixed content loading
- JS source map exposure (.map files with original source)
- Console errors / security warnings
- Angular/React/Vue security misconfigs
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("vapt.dom_scanner")

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Browser, Page
    PLAYWRIGHT_AVAILABLE = True
    logger.info("Playwright available — headless DOM scanning enabled")
except ImportError:
    logger.info("Playwright not installed — using static DOM analysis fallback")


@dataclass
class DOMFinding:
    test_id:     str
    title:       str
    description: str
    severity:    str
    url:         str
    evidence:    str
    remediation: str
    confidence:  float
    category:    str = "A03"
    cwe:         str = ""


# DOM XSS sinks — dangerous functions that render HTML/execute code
DOM_XSS_SINKS = [
    ("innerHTML",              "high",   "CWE-79"),
    ("outerHTML",              "high",   "CWE-79"),
    ("document.write",         "high",   "CWE-79"),
    ("document.writeln",       "high",   "CWE-79"),
    ("eval(",                  "critical","CWE-95"),
    ("setTimeout(",            "medium", "CWE-79"),
    ("setInterval(",           "medium", "CWE-79"),
    ("insertAdjacentHTML",     "high",   "CWE-79"),
    ("dangerouslySetInnerHTML","high",   "CWE-79"),
    ("v-html",                 "high",   "CWE-79"),
    ("bypassSecurityTrust",    "high",   "CWE-79"),  # Angular
    ("$sce.trustAsHtml",       "high",   "CWE-79"),  # AngularJS
]

# DOM XSS sources — user-controlled inputs
DOM_XSS_SOURCES = [
    "location.href", "location.search", "location.hash",
    "document.referrer", "document.cookie", "window.name",
    "document.URL", "document.documentURI", "document.baseURI",
    "localStorage.getItem", "sessionStorage.getItem",
    "history.state", "postMessage",
]

# Prototype pollution gadgets
PROTO_POLLUTION_PATTERNS = [
    r'__proto__\s*\[',
    r'constructor\s*\[\s*["\']prototype["\']',
    r'Object\.assign\s*\(\s*\w+\s*,',
    r'merge\s*\(\s*\w+\s*,\s*(?:req|body|data|input)',
    r'\.\s*__proto__\s*=',
]

# Sensitive data patterns in JS
SENSITIVE_JS_PATTERNS = [
    (r'(?:api_key|apikey|api-key)\s*[=:]\s*["\'][^"\']{8,}["\']', "API Key Exposed in JS", "critical"),
    (r'(?:password|passwd)\s*[=:]\s*["\'][^"\']{4,}["\']',        "Password in JS Source", "critical"),
    (r'(?:secret|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']',     "Secret in JS Source",  "critical"),
    (r'AKIA[0-9A-Z]{16}',                                          "AWS Key in JS",        "critical"),
    (r'(?:token|auth_token)\s*[=:]\s*["\'][A-Za-z0-9\-_\.]{20,}["\']', "Auth Token in JS","high"),
    (r'localStorage\.setItem\s*\(["\'](?:token|auth|password)',    "Sensitive Data in localStorage", "high"),
    (r'document\.cookie\s*=\s*[^;]+(?:password|token|secret)',     "Sensitive Cookie Set via JS", "high"),
    (r'//\s*#\s*sourceMappingURL\s*=',                             "JS Source Map Exposed", "medium"),
]

# postMessage vulnerabilities
POSTMESSAGE_UNSAFE = [
    r'addEventListener\s*\(\s*["\']message["\']',  # listens to postMessage
    r'postMessage\s*\(',                            # sends postMessage
]

# Mixed content patterns
MIXED_CONTENT = [
    r'(?:src|href|action)\s*=\s*["\']http://',
    r'url\s*\(\s*http://',
    r'fetch\s*\(\s*["\']http://',
    r'XMLHttpRequest.*open.*http://',
]


class DOMScanner:
    """
    Real DOM XSS and client-side vulnerability scanner.
    Uses Playwright for headless browser testing when available.
    Falls back to static JS analysis when not.
    """

    def __init__(self):
        self._findings: List[DOMFinding] = []
        self._browser: Optional[object] = None

    async def scan(
        self,
        target_url: str,
        client: httpx.AsyncClient,
        auth_headers: Dict[str, str] = None,
    ) -> List[DOMFinding]:
        self._findings = []

        if PLAYWRIGHT_AVAILABLE:
            await self._playwright_scan(target_url, auth_headers or {})
        else:
            await self._static_scan(target_url, client)

        # Always run static JS analysis
        await self._static_js_analysis(target_url, client)
        await self._check_source_maps(target_url, client)
        await self._check_clickjacking_real(target_url, client)

        logger.info(f"DOM scan complete: {len(self._findings)} findings")
        return self._findings

    # ── Playwright Headless Browser Scan ─────────────────────────────────────
    async def _playwright_scan(self, target_url: str, auth_headers: Dict[str, str]):
        """Full headless browser DOM XSS testing with real JS execution."""
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-web-security",  # for cross-origin testing
                    ]
                )
                context = await browser.new_context(
                    extra_http_headers=auth_headers,
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                # Collect console messages and errors
                console_msgs = []
                page_errors  = []
                page.on("console", lambda msg: console_msgs.append((msg.type, msg.text)))
                page.on("pageerror", lambda err: page_errors.append(str(err)))

                # Navigate to target
                try:
                    await page.goto(target_url, wait_until="networkidle", timeout=20000)
                except Exception as e:
                    logger.debug(f"Playwright navigation error: {e}")
                    await page.goto(target_url, timeout=15000)

                # Test 1: DOM XSS via URL hash
                await self._test_dom_xss_hash(page, target_url)

                # Test 2: DOM XSS via URL parameters
                await self._test_dom_xss_params(page, target_url)

                # Test 3: Prototype pollution
                await self._test_prototype_pollution(page, target_url)

                # Test 4: Sensitive data in page context
                await self._test_sensitive_context(page, target_url)

                # Test 5: postMessage handler security
                await self._test_postmessage(page, target_url)

                # Test 6: Console errors / security issues
                self._analyze_console(console_msgs, page_errors, target_url)

                await context.close()
                await browser.close()

        except Exception as e:
            logger.warning(f"Playwright scan error: {e} — falling back to static analysis")
            # Playwright failed — static analysis will still run

    async def _test_dom_xss_hash(self, page, target_url: str):
        """Test DOM XSS via URL hash injection."""
        xss_payloads = [
            "#<img src=x onerror=window._vaptxss=1>",
            "#javascript:window._vaptxss=1",
            "#'><img src=x onerror=window._vaptxss=1>",
        ]
        for payload in xss_payloads:
            try:
                test_url = target_url.split("#")[0] + payload
                await page.goto(test_url, timeout=8000)
                await page.wait_for_timeout(1500)
                # Check if our marker was set
                xss_triggered = await page.evaluate("() => window._vaptxss === 1")
                if xss_triggered:
                    self._add(DOMFinding(
                        test_id="DOM-XSS-HASH",
                        title="DOM XSS via URL Fragment (Hash)",
                        description=(
                            f"JavaScript injected via URL hash '{payload}' executed successfully. "
                            f"The page reads window.location.hash and passes it to a DOM sink "
                            f"without sanitization. Confirmed real execution."
                        ),
                        severity="high",
                        url=test_url,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"window._vaptxss === 1 after page load — XSS confirmed executed"
                        ),
                        remediation=(
                            "Never pass location.hash to innerHTML/eval/document.write. "
                            "Use DOMPurify. Set strict CSP."
                        ),
                        confidence=0.98,
                        category="A03",
                        cwe="CWE-79",
                    ))
                    return
            except Exception:
                pass

    async def _test_dom_xss_params(self, page, target_url: str):
        """Test DOM XSS via URL parameter injection."""
        parsed  = urlparse(target_url)
        if not parsed.query:
            return
        from urllib.parse import parse_qs, urlencode, urlunparse
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        for param in list(params.keys())[:3]:
            try:
                test_params = {**params, param: "<img src=x onerror=window._vaptxss=1>"}
                test_url    = urlunparse(parsed._replace(query=urlencode(test_params)))
                await page.goto(test_url, timeout=8000)
                await page.wait_for_timeout(1500)
                xss_triggered = await page.evaluate("() => window._vaptxss === 1")
                if xss_triggered:
                    self._add(DOMFinding(
                        test_id="DOM-XSS-PARAM",
                        title=f"DOM XSS via URL Parameter: '{param}'",
                        description=(
                            f"XSS payload in URL parameter '{param}' executed JavaScript. "
                            f"Confirmed real DOM XSS execution via headless browser."
                        ),
                        severity="high",
                        url=test_url,
                        evidence=(
                            f"Parameter: {param}\n"
                            f"Payload: <img src=x onerror=window._vaptxss=1>\n"
                            f"window._vaptxss === 1 — XSS confirmed"
                        ),
                        remediation="HTML-encode output. Use DOMPurify. Implement CSP.",
                        confidence=0.98,
                        category="A03",
                        cwe="CWE-79",
                    ))
            except Exception:
                pass

    async def _test_prototype_pollution(self, page, target_url: str):
        """Test for client-side prototype pollution."""
        try:
            await page.goto(target_url, timeout=10000)
            # Inject prototype pollution via URL hash
            poll_payloads = [
                "#__proto__[polluted]=vapttest",
                "#constructor[prototype][polluted]=vapttest",
            ]
            for payload in poll_payloads:
                test_url = target_url.split("#")[0] + payload
                await page.goto(test_url, timeout=8000)
                await page.wait_for_timeout(1000)
                polluted = await page.evaluate(
                    "() => ({}).polluted === 'vapttest' || Object.prototype.polluted === 'vapttest'"
                )
                if polluted:
                    self._add(DOMFinding(
                        test_id="DOM-PROTO-POLL",
                        title="Client-Side Prototype Pollution Confirmed",
                        description=(
                            f"Prototype pollution via '{payload}' successfully polluted "
                            f"Object.prototype. Attacker can inject properties into all objects, "
                            f"potentially escalating to XSS or RCE via gadget chains."
                        ),
                        severity="high",
                        url=test_url,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"Object.prototype.polluted === 'vapttest' — confirmed"
                        ),
                        remediation=(
                            "Freeze Object.prototype. Use Object.create(null) for lookups. "
                            "Sanitize keys against __proto__ and constructor."
                        ),
                        confidence=0.97,
                        category="A06",
                        cwe="CWE-1321",
                    ))
                    return
        except Exception:
            pass

    async def _test_sensitive_context(self, page, target_url: str):
        """Check for sensitive data exposed in JS page context."""
        try:
            await page.goto(target_url, timeout=10000)
            await page.wait_for_timeout(2000)
            # Check window variables for secrets
            sensitive_vars = await page.evaluate("""
                () => {
                    const found = [];
                    const sensitiveKeys = ['token','apikey','api_key','secret','password',
                                           'private_key','access_token','auth_token'];
                    for (const key of Object.keys(window)) {
                        if (sensitiveKeys.some(s => key.toLowerCase().includes(s))) {
                            found.push({key, type: typeof window[key]});
                        }
                    }
                    // Check __ENV__, __CONFIG__, APP_CONFIG etc
                    for (const configVar of ['__ENV__','__CONFIG__','APP_CONFIG','CONFIG',
                                              '__NEXT_DATA__','__NUXT__','__remixContext']) {
                        if (window[configVar]) {
                            const str = JSON.stringify(window[configVar]);
                            if (str.length > 10) found.push({key: configVar, preview: str.substring(0,200)});
                        }
                    }
                    return found;
                }
            """)
            if sensitive_vars:
                self._add(DOMFinding(
                    test_id="DOM-SENSITIVE-CTX",
                    title="Sensitive Data Exposed in JavaScript Context",
                    description=(
                        f"The following potentially sensitive variables are accessible "
                        f"in the browser's JavaScript context: "
                        f"{', '.join(v['key'] for v in sensitive_vars[:5])}. "
                        f"Any injected script or browser extension can access these."
                    ),
                    severity="high",
                    url=target_url,
                    evidence=f"window variables: {sensitive_vars[:5]}",
                    remediation=(
                        "Never expose secrets, tokens, or sensitive config in client-side JS. "
                        "Use server-side rendering for sensitive operations. "
                        "Audit window/global scope for sensitive data."
                    ),
                    confidence=0.80,
                    category="A02",
                    cwe="CWE-312",
                ))
        except Exception:
            pass

    async def _test_postmessage(self, page, target_url: str):
        """Check for insecure postMessage event handling."""
        try:
            src = await page.content()
            if "addEventListener" in src and "message" in src:
                # Check if origin is validated
                has_origin_check = bool(re.search(
                    r'(?:event|e|msg)\.origin\s*[!=]=|trusted[Oo]rigin|allowedOrigin',
                    src
                ))
                if not has_origin_check:
                    self._add(DOMFinding(
                        test_id="DOM-POSTMESSAGE",
                        title="Insecure postMessage Handler — No Origin Validation",
                        description=(
                            "The page listens for postMessage events without validating "
                            "the message origin. Any website can send messages and potentially "
                            "trigger sensitive actions or inject data."
                        ),
                        severity="medium",
                        url=target_url,
                        evidence="addEventListener('message') found without event.origin check",
                        remediation=(
                            "Always validate event.origin against an allowlist. "
                            "Never trust data from postMessage without origin verification."
                        ),
                        confidence=0.72,
                        category="A01",
                        cwe="CWE-346",
                    ))
        except Exception:
            pass

    def _analyze_console(self, msgs: list, errors: list, url: str):
        """Analyze browser console for security-relevant messages."""
        security_msgs = []
        for msg_type, text in msgs:
            if any(kw in text.lower() for kw in [
                "mixed content", "csp", "content security policy",
                "cors", "cross-origin", "unsafe", "blocked",
                "insecure", "certificate", "deprecated api"
            ]):
                security_msgs.append(f"[{msg_type}] {text[:200]}")

        if security_msgs:
            self._add(DOMFinding(
                test_id="DOM-CONSOLE-SECURITY",
                title="Security Warnings in Browser Console",
                description=(
                    f"The browser console reported {len(security_msgs)} security-relevant "
                    f"messages including mixed content, CSP violations, or CORS errors."
                ),
                severity="low",
                url=url,
                evidence="\n".join(security_msgs[:5]),
                remediation="Review and fix console security warnings — they indicate real security issues.",
                confidence=0.85,
                category="A05",
                cwe="CWE-16",
            ))

    # ── Static DOM Analysis Fallback ──────────────────────────────────────────
    async def _static_scan(self, target_url: str, client: httpx.AsyncClient):
        """Static JS source analysis when Playwright not available."""
        try:
            resp = await asyncio.wait_for(client.get(target_url), timeout=10)
            html = resp.text
            await self._analyze_js_content(html, target_url, "inline")

            # Fetch linked JS files
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
            for js_url in js_urls[:10]:
                full_url = urljoin(target_url, js_url)
                try:
                    js_resp = await asyncio.wait_for(client.get(full_url), timeout=8)
                    await self._analyze_js_content(js_resp.text, target_url, js_url)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Static DOM scan error: {e}")

    async def _analyze_js_content(self, content: str, page_url: str, source: str):
        """Analyze JS/HTML content for DOM vulnerabilities."""
        # DOM XSS sinks
        sink_hits = []
        for sink, severity, cwe in DOM_XSS_SINKS:
            if sink in content:
                # Check if a source is nearby (within 500 chars)
                idx = content.find(sink)
                surrounding = content[max(0, idx-200): idx+300]
                for src in DOM_XSS_SOURCES:
                    if src in surrounding:
                        sink_hits.append((sink, src, severity, cwe, surrounding[:300]))
                        break
                else:
                    # Sink present without obvious source — still flag
                    if sink in ["eval(", "document.write", "innerHTML"]:
                        sink_hits.append((sink, "unknown source", severity, cwe,
                                          content[max(0,idx-100):idx+200]))

        if sink_hits:
            sev = max((h[2] for h in sink_hits),
                      key=lambda s: {"critical":4,"high":3,"medium":2,"low":1}.get(s,0))
            self._add(DOMFinding(
                test_id="DOM-XSS-STATIC",
                title=f"DOM XSS Sinks Detected in JS ({source})",
                description=(
                    f"{len(sink_hits)} dangerous DOM sinks found with potential user-controlled sources: "
                    f"{', '.join(set(h[0] for h in sink_hits[:4]))}. "
                    f"Manual verification needed to confirm exploitability."
                ),
                severity=sev,
                url=page_url,
                evidence="\n---\n".join(
                    f"Sink: {h[0]} | Source: {h[1]}\n{h[4]}"
                    for h in sink_hits[:3]
                ),
                remediation=(
                    "Audit all DOM manipulation. Use textContent not innerHTML. "
                    "Apply DOMPurify for HTML. Implement strict CSP."
                ),
                confidence=0.65,
                category="A03",
                cwe="CWE-79",
            ))

        # Prototype pollution
        proto_hits = [p for p in PROTO_POLLUTION_PATTERNS if re.search(p, content)]
        if proto_hits:
            self._add(DOMFinding(
                test_id="DOM-PROTO-STATIC",
                title=f"Prototype Pollution Patterns in JS ({source})",
                description=(
                    f"Code patterns associated with prototype pollution: "
                    f"{proto_hits[:3]}. "
                    f"If user input reaches these patterns, Object.prototype can be polluted."
                ),
                severity="medium",
                url=page_url,
                evidence=f"Patterns: {proto_hits[:3]}",
                remediation="Use Object.create(null). Sanitize keys. Freeze Object.prototype.",
                confidence=0.60,
                category="A06",
                cwe="CWE-1321",
            ))

        # Sensitive data in JS
        for pattern, title, severity in SENSITIVE_JS_PATTERNS:
            match = re.search(pattern, content, re.I)
            if match:
                idx     = match.start()
                snippet = content[max(0,idx-20):idx+100]
                self._add(DOMFinding(
                    test_id=f"DOM-SECRET-{title[:10].replace(' ','')}",
                    title=title,
                    description=(
                        f"Sensitive data pattern '{title}' found in JavaScript source. "
                        f"Exposed to any user who views page source or JS files."
                    ),
                    severity=severity,
                    url=page_url,
                    evidence=f"Match in {source}: {snippet}",
                    remediation=(
                        "Never include secrets in client-side JavaScript. "
                        "Move to server-side. Use environment variables."
                    ),
                    confidence=0.82,
                    category="A02",
                    cwe="CWE-312",
                ))

        # Mixed content
        mixed = [p for p in MIXED_CONTENT if re.search(p, content, re.I)]
        if mixed and urlparse(page_url).scheme == "https":
            self._add(DOMFinding(
                test_id="DOM-MIXED-CONTENT",
                title="Mixed Content — HTTP Resources on HTTPS Page",
                description=(
                    "HTTPS page loads resources over HTTP — "
                    "these can be intercepted and replaced by a MITM attacker."
                ),
                severity="medium",
                url=page_url,
                evidence=f"Mixed content patterns: {mixed[:3]}",
                remediation="Load all resources over HTTPS. Use protocol-relative URLs (//).",
                confidence=0.80,
                category="A02",
                cwe="CWE-319",
            ))

    async def _static_js_analysis(self, target_url: str, client: httpx.AsyncClient):
        """Additional static analysis on fetched JS files."""
        if not PLAYWRIGHT_AVAILABLE:
            return  # Already done in _static_scan
        try:
            resp = await asyncio.wait_for(client.get(target_url), timeout=10)
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)
            for js_url in js_urls[:8]:
                full = urljoin(target_url, js_url)
                try:
                    jr = await asyncio.wait_for(client.get(full), timeout=8)
                    await self._analyze_js_content(jr.text, target_url, js_url)
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_source_maps(self, target_url: str, client: httpx.AsyncClient):
        """Check if JS source maps are exposed (leaks original source code)."""
        try:
            resp  = await asyncio.wait_for(client.get(target_url), timeout=8)
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', resp.text, re.I)
            for js_url in js_urls[:5]:
                map_url = urljoin(target_url, js_url) + ".map"
                try:
                    mr = await asyncio.wait_for(client.get(map_url), timeout=6)
                    if mr.status_code == 200 and "sources" in mr.text:
                        self._add(DOMFinding(
                            test_id="DOM-SOURCEMAP",
                            title=f"JavaScript Source Map Exposed: {js_url}.map",
                            description=(
                                f"Source map file '{map_url}' is publicly accessible. "
                                f"Source maps contain the original, unminified source code — "
                                f"business logic, credentials, internal paths, and comments "
                                f"visible to any attacker."
                            ),
                            severity="medium",
                            url=map_url,
                            evidence=f"HTTP {mr.status_code} | 'sources' key found | {len(mr.text)} bytes",
                            remediation=(
                                "Remove source maps from production deployments. "
                                "Restrict access to .map files in web server config. "
                                "Use --no-source-map in production build."
                            ),
                            confidence=0.95,
                            category="A05",
                            cwe="CWE-540",
                        ))
                except Exception:
                    pass
        except Exception:
            pass

    async def _check_clickjacking_real(self, target_url: str, client: httpx.AsyncClient):
        """Check if page can be embedded in iframe (clickjacking)."""
        try:
            resp  = await asyncio.wait_for(client.get(target_url), timeout=8)
            hdrs  = {k.lower(): v for k, v in resp.headers.items()}
            xfo   = hdrs.get("x-frame-options", "").upper()
            csp   = hdrs.get("content-security-policy", "").lower()
            protected = (
                xfo in ("DENY", "SAMEORIGIN") or
                "frame-ancestors" in csp
            )
            if not protected:
                body = resp.text[:2000].lower()
                has_forms = any(kw in body for kw in
                                ["<form", "login", "password", "submit", "transfer", "confirm"])
                if has_forms:
                    self._add(DOMFinding(
                        test_id="DOM-CLICKJACK",
                        title="Clickjacking — Interactive Page Embeddable in iframe",
                        description=(
                            "Page contains interactive forms/login and has no clickjacking protection. "
                            "Attacker can embed this page in a transparent iframe and trick users "
                            "into clicking buttons or submitting forms unknowingly."
                        ),
                        severity="medium",
                        url=target_url,
                        evidence=(
                            f"X-Frame-Options: {xfo or 'NOT SET'}\n"
                            f"CSP frame-ancestors: {'SET' if 'frame-ancestors' in csp else 'NOT SET'}\n"
                            f"Page contains interactive elements"
                        ),
                        remediation=(
                            "Add X-Frame-Options: DENY. "
                            "Add Content-Security-Policy: frame-ancestors 'none'."
                        ),
                        confidence=0.88,
                        category="A05",
                        cwe="CWE-1021",
                    ))
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _add(self, finding: DOMFinding):
        key = (finding.test_id, finding.url)
        if key not in {(f.test_id, f.url) for f in self._findings}:
            self._findings.append(finding)

    def get_findings(self) -> List[DOMFinding]:
        return list(self._findings)
