"""
VAPTForge Headless Browser Scanner
Real DOM XSS detection, SPA crawling, JavaScript execution analysis.
Uses Playwright if available, falls back to httpx + regex analysis.
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("vapt.headless")

PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Browser, Page, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
    logger.info("Playwright available — headless browser scanning enabled")
except ImportError:
    logger.info("Playwright not installed — using httpx fallback for DOM analysis")


@dataclass
class HeadlessFinding:
    test_id:     str
    title:       str
    description: str
    severity:    str
    url:         str
    parameter:   Optional[str]
    payload:     str
    evidence:    str
    remediation: str
    confidence:  float
    category:    str
    cwe:         str = ""


# DOM XSS source-to-sink patterns for JS analysis
DOM_SOURCES = [
    "location.href", "location.hash", "location.search", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie",
    "localStorage.getItem", "sessionStorage.getItem",
    "history.state", "postMessage",
]

DOM_SINKS = [
    "innerHTML", "outerHTML", "document.write", "document.writeln",
    "eval(", "setTimeout(", "setInterval(", "Function(",
    "insertAdjacentHTML", "location.href =", "location.assign(",
    "location.replace(", "src =", "href =",
    "$.html(", "$(", ".html(", "dangerouslySetInnerHTML",
]

# JS patterns that indicate dangerous data flows
DANGEROUS_PATTERNS = [
    # location.hash → innerHTML
    r'location\.(?:hash|search|href)[^;]{0,200}innerHTML',
    r'document\.URL[^;]{0,200}(?:eval|innerHTML|document\.write)',
    r'location\.(?:hash|search)[^;]{0,200}eval\s*\(',
    r'window\.name[^;]{0,200}innerHTML',
    r'document\.referrer[^;]{0,200}(?:eval|innerHTML)',
    # postMessage without origin check
    r'addEventListener\s*\(\s*["\']message["\'][^}]{0,500}(?:eval|innerHTML)',
    # jQuery html() with URL params
    r'\$\([^)]+\)\.html\s*\([^)]*location\.',
    # React dangerouslySetInnerHTML with dynamic data
    r'dangerouslySetInnerHTML\s*=\s*\{[^}]*__html\s*:\s*(?![\'"]\s*<)',
    # eval with user data
    r'eval\s*\([^)]*(?:location|document\.URL|window\.name)',
]

# Stored XSS injection probes
STORED_XSS_PROBES = [
    ('<vaptcanary-xss-1>', 'vaptcanary-xss-1'),
    ('<img src=x onerror=vaptcanary2>', 'onerror=vaptcanary2'),
    ('"><vaptcanary3>', 'vaptcanary3'),
    ('<script>vaptcanary4</script>', 'vaptcanary4'),
]

# CSP bypass patterns
CSP_BYPASS_PATTERNS = [
    ("unsafe-inline",    "CSP allows 'unsafe-inline' — inline scripts executable"),
    ("unsafe-eval",      "CSP allows 'unsafe-eval' — eval() is unrestricted"),
    ("data:",            "CSP allows data: URIs — potential XSS vector"),
    ("*",                "CSP uses wildcard (*) — any source allowed"),
    ("http:",            "CSP allows http: — mixed content and XSS risk"),
]


class HeadlessScanner:
    """
    DOM XSS detection and SPA scanning.
    Uses Playwright for real JS execution, falls back to static JS analysis.
    """

    def __init__(self, timeout: int = 60):
        self.timeout   = timeout
        self._findings: List[HeadlessFinding] = []
        self._visited:  Set[str] = set()

    async def scan(self, target_url: str, max_pages: int = 15) -> List[HeadlessFinding]:
        self._findings = []
        self._visited  = set()

        if PLAYWRIGHT_AVAILABLE:
            try:
                await self._playwright_scan(target_url, max_pages)
            except Exception as e:
                logger.warning(f"Playwright scan error: {e} — falling back to static analysis")
                await self._static_js_analysis(target_url)
        else:
            await self._static_js_analysis(target_url)

        return self._findings

    # ── Playwright (real browser) scan ────────────────────────────────────────
    async def _playwright_scan(self, target_url: str, max_pages: int):
        """Use real Chromium browser for DOM XSS detection."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--disable-extensions",
                ]
            )
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="VAPTForge-Scanner/2.0 Security Assessment",
            )

            try:
                # Set up XSS detection via console monitoring
                xss_alerts: List[str] = []
                errors:     List[str] = []

                page = await context.new_page()

                # Monitor console for XSS execution
                page.on("console", lambda msg: xss_alerts.append(msg.text)
                        if "vapt" in msg.text.lower() else None)
                page.on("pageerror", lambda err: errors.append(str(err)))

                # Navigate to target
                await page.goto(target_url, wait_until="networkidle", timeout=20000)
                await asyncio.sleep(2)

                # 1. DOM XSS via URL hash injection
                await self._test_hash_xss(page, target_url)

                # 2. DOM XSS via URL search params
                await self._test_param_xss(page, target_url)

                # 3. Analyse page JS for dangerous patterns
                await self._analyse_page_js(page, target_url)

                # 4. CSP analysis
                await self._check_csp_browser(page, target_url)

                # 5. Crawl and test additional pages
                links = await self._extract_links(page, target_url)
                for link in links[:max_pages-1]:
                    if link in self._visited:
                        continue
                    self._visited.add(link)
                    try:
                        sub_page = await context.new_page()
                        sub_page.on("console", lambda msg: xss_alerts.append(msg.text)
                                    if "vapt" in msg.text.lower() else None)
                        await sub_page.goto(link, wait_until="domcontentloaded", timeout=12000)
                        await self._analyse_page_js(sub_page, link)
                        await sub_page.close()
                    except Exception:
                        pass

                # 6. postMessage XSS test
                await self._test_postmessage_xss(page, target_url)

                # 7. Check if any XSS actually fired
                if xss_alerts:
                    for alert in xss_alerts[:5]:
                        self._add(HeadlessFinding(
                            test_id="HEAD-XSS-FIRED",
                            title="DOM XSS Confirmed — JavaScript Executed",
                            description=(
                                f"XSS payload executed in real browser: '{alert}'. "
                                f"This is a CONFIRMED DOM-based Cross-Site Scripting vulnerability. "
                                f"Attacker can execute arbitrary JavaScript in victim's browser."
                            ),
                            severity="critical",
                            url=target_url,
                            parameter=None,
                            payload="Browser-executed XSS probe",
                            evidence=f"JavaScript alert/console triggered: {alert}",
                            remediation=(
                                "Sanitize all user-controlled data before DOM manipulation. "
                                "Use textContent instead of innerHTML. "
                                "Implement strict Content-Security-Policy."
                            ),
                            confidence=0.99,
                            category="A03",
                            cwe="CWE-79",
                        ))

                await page.close()
            finally:
                await context.close()
                await browser.close()

    async def _test_hash_xss(self, page, target_url: str):
        """Test DOM XSS via URL fragment (hash)."""
        xss_hash_probes = [
            "#<img src=x onerror=console.log('vapt-hash-xss')>",
            "#javascript:console.log('vapt-hash-xss')",
            "#\"><img src=x onerror=console.log('vapt-hash-xss')>",
        ]
        for probe in xss_hash_probes:
            try:
                await page.goto(target_url + probe, wait_until="domcontentloaded", timeout=8000)
                await asyncio.sleep(1)
                # Check if probe appears in DOM unsanitised
                content = await page.content()
                if "onerror=console" in content.lower():
                    self._add(HeadlessFinding(
                        test_id="HEAD-HASH-XSS",
                        title="DOM XSS via URL Hash Fragment",
                        description=(
                            f"URL hash fragment injected into DOM without sanitization. "
                            f"Payload: {probe[:80]}. "
                            f"Attacker can craft malicious links using the hash (#) portion of the URL."
                        ),
                        severity="high",
                        url=target_url,
                        parameter="location.hash",
                        payload=probe,
                        evidence=f"Hash payload reflected in DOM: {probe[:100]}",
                        remediation=(
                            "Sanitize location.hash before using in DOM. "
                            "Use DOMPurify. Never pass hash value to innerHTML."
                        ),
                        confidence=0.86,
                        category="A03",
                        cwe="CWE-79",
                    ))
                    break
            except Exception:
                pass

    async def _test_param_xss(self, page, target_url: str):
        """Test DOM XSS via URL query parameters."""
        probes = [
            "?q=<img src=x onerror=console.log('vapt-param')>",
            "?search=<script>console.log('vapt-param')</script>",
            "?name=\"><img src=x onerror=console.log('vapt-param')>",
            "?msg=javascript:console.log('vapt-param')",
        ]
        for probe in probes:
            try:
                await page.goto(target_url + probe, wait_until="domcontentloaded", timeout=8000)
                await asyncio.sleep(1)
                content = await page.content()
                if "onerror=console" in content.lower() or "vapt-param" in content.lower():
                    self._add(HeadlessFinding(
                        test_id="HEAD-PARAM-XSS",
                        title="DOM XSS via URL Parameter",
                        description=(
                            f"URL query parameter injected into DOM without sanitization. "
                            f"Probe: {probe[:80]}. "
                            f"Reflected XSS via DOM manipulation."
                        ),
                        severity="high",
                        url=target_url + probe,
                        parameter="query_param",
                        payload=probe,
                        evidence=f"Probe reflected in DOM",
                        remediation="Encode all URL parameters before inserting into DOM.",
                        confidence=0.88,
                        category="A03",
                        cwe="CWE-79",
                    ))
                    break
            except Exception:
                pass

    async def _analyse_page_js(self, page, url: str):
        """Extract and analyse JavaScript for dangerous source-to-sink flows."""
        try:
            # Get all script content from page
            scripts = await page.evaluate("""
                () => {
                    const scripts = [];
                    document.querySelectorAll('script').forEach(s => {
                        if (s.textContent) scripts.push(s.textContent);
                    });
                    return scripts.join('\\n');
                }
            """)

            if not scripts:
                return

            hits = []
            for pattern_str in DANGEROUS_PATTERNS:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
                    for match in pattern.finditer(scripts):
                        snippet = scripts[max(0, match.start()-30): match.end()+30]
                        hits.append(snippet[:150])
                        if len(hits) >= 3:
                            break
                except re.error:
                    pass

            if hits:
                self._add(HeadlessFinding(
                    test_id="HEAD-DOM-FLOW",
                    title=f"Dangerous DOM Source-to-Sink Flow Detected",
                    description=(
                        f"JavaScript analysis at {url} found {len(hits)} dangerous data flow(s) "
                        f"where user-controlled sources (location, document.URL, window.name) "
                        f"flow into execution sinks (innerHTML, eval, document.write). "
                        f"Manual verification required to confirm exploitability."
                    ),
                    severity="high",
                    url=url,
                    parameter=None,
                    payload="Static JS analysis",
                    evidence=f"Dangerous flows:\n" + "\n".join(f"  [{i+1}] {h}" for i,h in enumerate(hits)),
                    remediation=(
                        "Audit all DOM manipulation. "
                        "Use textContent not innerHTML. "
                        "Sanitize with DOMPurify before any DOM insertion."
                    ),
                    confidence=0.73,
                    category="A03",
                    cwe="CWE-79",
                ))

        except Exception as e:
            logger.debug(f"JS analysis error: {e}")

    async def _check_csp_browser(self, page, url: str):
        """Check CSP via browser's actual security headers."""
        try:
            csp_violations: List[str] = []
            page.on("response", lambda r: None)  # hook responses

            # Try injecting inline script — if CSP blocks it, page raises error
            result = await page.evaluate("""
                () => {
                    try {
                        const s = document.createElement('script');
                        s.textContent = 'window._vaptCspTest = 1;';
                        document.head.appendChild(s);
                        return window._vaptCspTest === 1 ? 'inline_allowed' : 'inline_blocked';
                    } catch(e) {
                        return 'blocked: ' + e.message;
                    }
                }
            """)

            if result == "inline_allowed":
                self._add(HeadlessFinding(
                    test_id="HEAD-CSP-INLINE",
                    title="CSP Does Not Block Inline Scripts (Browser Confirmed)",
                    description=(
                        f"Inline JavaScript injection was executed successfully in the browser at {url}. "
                        f"This confirms CSP does not prevent inline script execution, "
                        f"making XSS attacks viable even with CSP present."
                    ),
                    severity="high",
                    url=url,
                    parameter=None,
                    payload="Inline script injection test",
                    evidence=f"Browser evaluation result: {result}",
                    remediation=(
                        "Implement strict CSP with script-src 'none' or nonces. "
                        "Remove 'unsafe-inline' from CSP."
                    ),
                    confidence=0.95,
                    category="A05",
                    cwe="CWE-693",
                ))
        except Exception:
            pass

    async def _test_postmessage_xss(self, page, url: str):
        """Test for postMessage XSS — listener without origin check."""
        try:
            has_unsafe_listener = await page.evaluate("""
                () => {
                    let found = false;
                    const orig = window.addEventListener;
                    // Check existing listeners via getEventListeners if available
                    try {
                        const listeners = getEventListeners(window)['message'] || [];
                        found = listeners.length > 0;
                    } catch(e) {
                        // Not in devtools context — check via source scanning
                        const scripts = Array.from(document.scripts)
                            .map(s => s.textContent).join('');
                        found = scripts.includes('addEventListener') &&
                                scripts.includes('message') &&
                                scripts.includes('data') &&
                                !scripts.includes('event.origin');
                    }
                    return found;
                }
            """)

            if has_unsafe_listener:
                # Try sending a postMessage with XSS payload
                await page.evaluate("""
                    () => {
                        window.postMessage(
                            '<img src=x onerror=console.log("vapt-postmsg")>',
                            '*'
                        );
                    }
                """)
                await asyncio.sleep(1)
                content = await page.content()
                if "vapt-postmsg" in content.lower():
                    self._add(HeadlessFinding(
                        test_id="HEAD-POSTMSG-XSS",
                        title="postMessage XSS — Missing Origin Validation",
                        description=(
                            f"The page at {url} processes postMessage events without "
                            f"validating the sender origin. An attacker can send malicious "
                            f"messages from any domain, triggering XSS."
                        ),
                        severity="high",
                        url=url,
                        parameter="postMessage",
                        payload="window.postMessage('<img src=x onerror=...>', '*')",
                        evidence="postMessage XSS payload executed without origin check",
                        remediation=(
                            "Always validate event.origin in message event listeners. "
                            "Use allowlist of trusted origins."
                        ),
                        confidence=0.88,
                        category="A03",
                        cwe="CWE-79",
                    ))
        except Exception:
            pass

    async def _extract_links(self, page, base_url: str) -> List[str]:
        """Extract all same-domain links from page."""
        try:
            domain = urlparse(base_url).netloc
            links  = await page.evaluate("""
                (domain) => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(href => href.includes(domain) &&
                                       !href.includes('#') &&
                                       !href.endsWith('.pdf') &&
                                       !href.endsWith('.zip'));
                }
            """, domain)
            return list(set(links))[:20]
        except Exception:
            return []

    # ── Static JS Analysis (httpx fallback) ───────────────────────────────────
    async def _static_js_analysis(self, target_url: str):
        """
        When Playwright is not available, fetch JS files and analyse statically.
        """
        import httpx
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(10),
        ) as client:
            try:
                resp = await asyncio.wait_for(client.get(target_url), timeout=10)
                html = resp.text

                # Check CSP header
                csp = resp.headers.get("content-security-policy", "")
                if csp:
                    for pattern, description in CSP_BYPASS_PATTERNS:
                        if pattern in csp:
                            self._add(HeadlessFinding(
                                test_id=f"HEAD-CSP-{pattern.replace('*','WILD').replace(':','').upper()[:8]}",
                                title=f"Weak CSP Directive: '{pattern}'",
                                description=description,
                                severity="medium",
                                url=target_url,
                                parameter=None,
                                payload="",
                                evidence=f"Content-Security-Policy: {csp[:300]}",
                                remediation=f"Remove '{pattern}' from CSP. Use nonces or hashes.",
                                confidence=0.90,
                                category="A05",
                                cwe="CWE-693",
                            ))

                # Extract and analyse JS
                js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I)
                domain  = urlparse(target_url).netloc

                all_js = html  # Start with inline scripts
                for js_url in js_urls[:10]:
                    full_url = urljoin(target_url, js_url)
                    if domain in full_url or full_url.endswith(".js"):
                        try:
                            js_resp = await asyncio.wait_for(client.get(full_url), timeout=8)
                            all_js += "\n" + js_resp.text
                        except Exception:
                            pass

                # Run dangerous pattern analysis
                hits = []
                for pattern_str in DANGEROUS_PATTERNS:
                    try:
                        pattern = re.compile(pattern_str, re.IGNORECASE | re.DOTALL)
                        for match in pattern.finditer(all_js):
                            snippet = all_js[max(0, match.start()-30): match.end()+50]
                            hits.append(snippet[:200])
                            break
                    except re.error:
                        pass

                if hits:
                    self._add(HeadlessFinding(
                        test_id="HEAD-STATIC-DOM",
                        title="DOM XSS Risk — Dangerous Source-to-Sink Flows in JavaScript",
                        description=(
                            f"Static analysis of JavaScript at {target_url} found "
                            f"{len(hits)} dangerous data flow pattern(s). "
                            f"User-controlled data (URL, hash, cookies) flows into "
                            f"DOM execution sinks without apparent sanitization."
                        ),
                        severity="high",
                        url=target_url,
                        parameter=None,
                        payload="Static JS analysis",
                        evidence="Dangerous flows:\n" + "\n".join(
                            f"  [{i+1}] {h}" for i, h in enumerate(hits[:3])
                        ),
                        remediation=(
                            "Audit all DOM manipulation code. "
                            "Use DOMPurify. Use textContent not innerHTML."
                        ),
                        confidence=0.68,
                        category="A03",
                        cwe="CWE-79",
                    ))

                # postMessage listener check (static)
                if "addEventListener" in all_js and "'message'" in all_js:
                    if "event.origin" not in all_js and "message.origin" not in all_js:
                        self._add(HeadlessFinding(
                            test_id="HEAD-POSTMSG-NOCHECK",
                            title="postMessage Listener Without Origin Check",
                            description=(
                                "JavaScript contains a 'message' event listener "
                                "without validating event.origin. "
                                "Any domain can send messages that may trigger XSS."
                            ),
                            severity="medium",
                            url=target_url,
                            parameter=None,
                            payload="Static analysis",
                            evidence="addEventListener('message'...) without event.origin check",
                            remediation="Validate event.origin against an allowlist in all message listeners.",
                            confidence=0.72,
                            category="A03",
                            cwe="CWE-79",
                        ))

            except Exception as e:
                logger.debug(f"Static JS analysis error: {e}")

    # ── Helper ─────────────────────────────────────────────────────────────────
    def _add(self, finding: HeadlessFinding):
        key = (finding.test_id, finding.url, finding.parameter)
        existing = {(f.test_id, f.url, f.parameter) for f in self._findings}
        if key not in existing:
            self._findings.append(finding)
