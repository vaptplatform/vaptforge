"""
VAPTForge Scanner Engine v2.0 — Full Pipeline with SAST + DAST + DOM + OOB + Auth
Crawl → Traffic Collection → OWASP Modules → SAST → DOM Scanner → OOB Detection →
Authenticated Scanning → CVSS Scoring → Notify

New in v2.0:
  - Authenticated scanning (form/bearer/basic/apikey)
  - Headless DOM XSS detection (Playwright)
  - Out-of-band blind detection (SSRF/SQLi/XXE/XSS)
  - Privilege escalation testing post-auth
  - Source map exposure detection
  - postMessage vulnerability detection
Timeout: 90 seconds maximum (extended for deeper scanning)
Govt-grade: raw HTTP evidence capture + CVSS v3 scoring per finding
"""
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

import httpx
from bs4 import BeautifulSoup

from app.core.config import settings
from app.core.websocket_manager import ScanLogEntry, websocket_manager
from app.models.models import Finding, Scan, ScanStatus, Severity
from app.scanner.modules.base import BaseModule, ScanContext, RawFinding
from app.scanner.traffic_collector import TrafficCollector
from app.scanner.auth_scanner import AuthConfig, AuthenticatedScanner
from app.scanner.oob_detector import OOBDetector
from app.scanner.dom_scanner import DOMScanner

logger = logging.getLogger("vapt.engine")

SCAN_TIMEOUT = 90  # seconds (extended for deeper scanning)

# ── CVSS v3 base score lookup per OWASP category + severity ──────────────────
# These are conservative representative scores for automated findings.
# Manual testers may adjust after verification.
CVSS_TABLE = {
    # (owasp_category, severity) -> cvss_score
    ("A01", "critical"): 9.8, ("A01", "high"): 8.1, ("A01", "medium"): 6.5, ("A01", "low"): 4.3,
    ("A02", "critical"): 9.1, ("A02", "high"): 7.5, ("A02", "medium"): 5.9, ("A02", "low"): 3.7,
    ("A03", "critical"): 9.8, ("A03", "high"): 8.8, ("A03", "medium"): 6.1, ("A03", "low"): 4.0,
    ("A04", "critical"): 8.5, ("A04", "high"): 7.2, ("A04", "medium"): 5.4, ("A04", "low"): 3.1,
    ("A05", "critical"): 9.1, ("A05", "high"): 7.5, ("A05", "medium"): 5.3, ("A05", "low"): 2.7,
    ("A06", "critical"): 9.8, ("A06", "high"): 8.1, ("A06", "medium"): 6.2, ("A06", "low"): 4.0,
    ("A07", "critical"): 9.4, ("A07", "high"): 8.2, ("A07", "medium"): 6.5, ("A07", "low"): 4.2,
    ("A08", "critical"): 9.0, ("A08", "high"): 7.7, ("A08", "medium"): 5.5, ("A08", "low"): 3.0,
    ("A09", "critical"): 7.5, ("A09", "high"): 6.3, ("A09", "medium"): 4.3, ("A09", "low"): 2.0,
    ("A10", "critical"): 9.8, ("A10", "high"): 8.6, ("A10", "medium"): 6.4, ("A10", "low"): 4.1,
}

def _cvss_score(owasp_cat: str, severity: str) -> float:
    key = (owasp_cat.upper()[:3], severity.lower())
    return CVSS_TABLE.get(key, {"critical":7.0,"high":5.5,"medium":3.5,"low":1.5,"info":0.0}.get(severity.lower(), 3.0))

def _cvss_vector(owasp_cat: str, severity: str) -> str:
    """Return a representative CVSS v3.1 vector string."""
    vectors = {
        "A01": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "A02": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A03": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "A04": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "A05": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "A06": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "A07": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "A08": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "A09": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "A10": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    return vectors.get(owasp_cat.upper()[:3], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")


def _load_all_modules() -> List[BaseModule]:
    from app.scanner.modules.a01_broken_access_control import BrokenAccessControlModule
    from app.scanner.modules.a02_crypto_failures       import CryptoFailuresModule
    from app.scanner.modules.a03_injection             import InjectionDetectionModule
    from app.scanner.modules.a04_insecure_design       import InsecureDesignModule
    from app.scanner.modules.a05_security_misconfig    import SecurityMisconfigModule
    from app.scanner.modules.a06_vulnerable_components import VulnerableComponentsModule
    from app.scanner.modules.a07_auth_failures         import AuthFailuresModule
    from app.scanner.modules.a08_integrity_failures    import IntegrityFailuresModule
    from app.scanner.modules.a09_logging_failures      import LoggingFailuresModule
    from app.scanner.modules.a10_ssrf                  import SSRFModule
    return [
        BrokenAccessControlModule(), CryptoFailuresModule(),
        InjectionDetectionModule(),  InsecureDesignModule(),
        SecurityMisconfigModule(),   VulnerableComponentsModule(),
        AuthFailuresModule(),        IntegrityFailuresModule(),
        LoggingFailuresModule(),     SSRFModule(),
    ]


class ScannerEngine:
    def __init__(self, scan: Scan, db_session):
        self.scan    = scan
        self.db      = db_session
        self.scan_id = scan.id
        self.target_url    = scan.target_url
        self.target_domain = scan.target_domain

        self._visited:  Set[str]         = set()
        self._queue:    asyncio.Queue    = asyncio.Queue()
        self._findings: List[RawFinding] = []
        self._total_requests = 0
        self._start_time     = time.time()
        self._traffic        = TrafficCollector(scan.id)

        # Raw HTTP evidence store: url -> {request, response}
        self._http_evidence: Dict[str, dict] = {}

        # v2.0: Auth, OOB, DOM scanners
        scan_opts = scan.scan_options or {}
        self._auth_config  = AuthConfig.from_scan_options(scan_opts)
        self._auth_scanner = AuthenticatedScanner(self._auth_config, None)  # client set after init
        self._oob_detector = OOBDetector(scan.id)
        self._dom_scanner  = DOMScanner()
        self._auth_headers: Dict[str, str] = {}

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(8),
            headers={"User-Agent": settings.SCANNER_USER_AGENT},
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        )
        # Bind auth scanner to real client
        self._auth_scanner.client = self._client

        enabled = scan.enabled_modules or {}
        all_mods = _load_all_modules()
        self._modules = [m for m in all_mods if enabled.get(m.module_id, True)] if enabled else all_mods
        logger.info(f"[{self.scan_id[:8]}] {len(self._modules)} modules loaded → {self.target_url}")

    def _elapsed(self)   -> float: return time.time() - self._start_time
    def _timed_out(self) -> bool:  return self._elapsed() >= SCAN_TIMEOUT

    async def run(self) -> None:
        try:
            await self._set_status(ScanStatus.RUNNING)
            await self._log("INFO", f"Scan started — {self.target_url}", progress=0)
            await self._log("INFO", f"{len(self._modules)} OWASP modules active | Timeout: {SCAN_TIMEOUT}s")

            if not await self._connectivity():
                raise RuntimeError(f"Target unreachable: {self.target_url}")

            # v2.0 Phase 0: Authenticated scanning setup
            if self._auth_config.is_enabled and not self._timed_out():
                await self._auth_phase()

            if not self._timed_out(): await self._header_phase()
            if not self._timed_out(): await self._sast_phase()
            if not self._timed_out():
                await self._queue.put((self.target_url, 0))
                await self._crawl_phase()
            if not self._timed_out(): await self._post_crawl()

            # v2.0 Phase: DOM Scanner (headless browser)
            if not self._timed_out():
                await self._dom_phase()

            # v2.0 Phase: Out-of-Band detection
            if not self._timed_out():
                await self._oob_phase()

            # v2.0 Phase: Privilege escalation (if authenticated)
            if not self._timed_out() and self._auth_scanner.is_authenticated:
                await self._privesc_phase()

            await self._finalize()

        except asyncio.CancelledError:
            await self._set_status(ScanStatus.CANCELLED)
            await self._log("WARN", "Scan cancelled")
        except Exception as exc:
            logger.exception(f"Scan {self.scan_id} error: {exc}")
            await self._set_status(ScanStatus.FAILED, error=str(exc))
            await self._log("ERROR", f"Scan failed: {exc}")
        finally:
            await self._client.aclose()

    # ── Raw HTTP evidence capture ─────────────────────────────────────────────
    def _capture_http_evidence(self, url: str, resp: httpx.Response, ms: int) -> dict:
        """Capture full raw HTTP request + response for govt-grade evidence."""
        try:
            req = resp.request
            # Build raw request string
            req_line    = f"{req.method} {req.url.path or '/'} HTTP/1.1"
            req_headers = "\r\n".join(f"{k}: {v}" for k, v in req.headers.items())
            try:
                req_body = req.content.decode("utf-8", errors="replace")[:500]
            except Exception:
                req_body = ""
            raw_request = f"{req_line}\r\n{req_headers}\r\n\r\n{req_body}"

            # Build raw response string
            status_line   = f"HTTP/1.1 {resp.status_code}"
            resp_headers  = "\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            resp_body     = resp.text[:2000] if resp.text else ""
            raw_response  = f"{status_line}\r\n{resp_headers}\r\n\r\n{resp_body}"

            return {
                "raw_request":   raw_request[:3000],
                "raw_response":  raw_response[:3000],
                "request_url":   str(req.url),
                "request_method": req.method,
                "request_headers": dict(req.headers),
                "response_status": resp.status_code,
                "response_headers": dict(resp.headers),
                "response_size_bytes": len(resp.content),
                "response_time_ms": ms,
                "protocol": urlparse(url).scheme.upper(),
                "captured_at": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            logger.debug(f"HTTP evidence capture error: {e}")
            return {"raw_request": "", "raw_response": "", "response_status": 0}

    async def _connectivity(self) -> bool:
        try:
            t0   = time.time()
            resp = await self._client.head(self.target_url)
            ms   = int((time.time() - t0) * 1000)
            evidence = self._capture_http_evidence(self.target_url, resp, ms)
            self._http_evidence[self.target_url] = evidence
            await self._log("INFO", f"Connected — HTTP {resp.status_code} ({ms}ms)", url=self.target_url, progress=3)
            return True
        except Exception as e:
            await self._log("ERROR", f"Cannot reach target: {e}")
            return False

    # ── v2.0 Auth Phase ───────────────────────────────────────────────────────
    async def _auth_phase(self) -> None:
        await self._log("SCAN", "Authenticating with target…", url=self.target_url, progress=2)
        try:
            result = await self._auth_scanner.authenticate(self.target_url)
            if result.success:
                self._auth_headers = result.headers
                # Update client headers with auth
                self._client.headers.update(result.headers)
                if result.cookies:
                    for k, v in result.cookies.items():
                        self._client.cookies.set(k, v)
                await self._log(
                    "INFO",
                    f"Authentication successful ({result.method}) — scanning as authenticated user",
                    url=self.target_url, progress=4,
                )
                logger.info(f"Auth success: method={result.method}, "
                            f"headers={list(result.headers.keys())}, "
                            f"cookies={list(result.cookies.keys())}")
            else:
                await self._log(
                    "WARN",
                    f"Authentication failed ({result.method}): {result.error} — scanning anonymously",
                    url=self.target_url,
                )
        except Exception as e:
            logger.warning(f"Auth phase error: {e}")
            await self._log("WARN", f"Auth phase error: {e}")

    # ── v2.0 DOM Scanner Phase ────────────────────────────────────────────────
    async def _dom_phase(self) -> None:
        await self._log("SCAN", "Running DOM scanner (headless browser analysis)…",
                        url=self.target_url, progress=78)
        try:
            dom_findings = await asyncio.wait_for(
                self._dom_scanner.scan(
                    self.target_url,
                    self._client,
                    auth_headers=self._auth_headers,
                ),
                timeout=25,
            )
            count = 0
            for df in dom_findings:
                raw = RawFinding(
                    test_id=df.test_id,
                    owasp_category=df.category,
                    title=f"[DOM] {df.title}",
                    description=df.description,
                    severity=getattr(Severity, df.severity.upper(), Severity.MEDIUM),
                    url=df.url,
                    parameter=None,
                    evidence={"dom_evidence": df.evidence, "detection": "dom_scanner"},
                    remediation=df.remediation,
                    confidence=df.confidence,
                    cwe=df.cwe,
                    references=[],
                )
                self._findings.append(raw)
                count += 1
            await self._log("INFO", f"DOM scan complete: {count} findings", progress=83)
        except asyncio.TimeoutError:
            await self._log("WARN", "DOM scan timed out", progress=83)
        except Exception as e:
            logger.warning(f"DOM phase error: {e}")
            await self._log("WARN", f"DOM phase error: {e}")

    # ── v2.0 OOB Detection Phase ──────────────────────────────────────────────
    async def _oob_phase(self) -> None:
        await self._log("SCAN", "Running out-of-band blind vulnerability detection…",
                        url=self.target_url, progress=85)
        try:
            crawled = list(self._visited)
            oob_findings = await asyncio.wait_for(
                self._oob_detector.run_all(
                    self.target_url,
                    crawled,
                    self._client,
                ),
                timeout=25,
            )
            count = 0
            for of in oob_findings:
                raw = RawFinding(
                    test_id=of.test_id,
                    owasp_category=of.category,
                    title=f"[OOB] {of.title}",
                    description=of.description,
                    severity=getattr(Severity, of.severity.upper(), Severity.HIGH),
                    url=of.url,
                    parameter=of.parameter,
                    evidence={"oob_evidence": of.evidence, "payload": of.payload,
                               "detection": "oob_detector"},
                    remediation=of.remediation,
                    confidence=of.confidence,
                    cwe=of.cwe,
                    references=[],
                )
                self._findings.append(raw)
                count += 1
            await self._log("INFO", f"OOB detection complete: {count} findings", progress=90)
        except asyncio.TimeoutError:
            await self._log("WARN", "OOB detection timed out", progress=90)
        except Exception as e:
            logger.warning(f"OOB phase error: {e}")
            await self._log("WARN", f"OOB phase error: {e}")

    # ── v2.0 Privilege Escalation Phase ──────────────────────────────────────
    async def _privesc_phase(self) -> None:
        await self._log("SCAN", "Testing privilege escalation as authenticated user…",
                        url=self.target_url, progress=92)
        try:
            admin_paths = [
                "/admin", "/admin/users", "/admin/dashboard", "/admin/config",
                "/api/admin", "/management", "/superadmin", "/api/v1/admin",
                "/api/users", "/api/config", "/internal",
            ]
            privesc_findings = await asyncio.wait_for(
                self._auth_scanner.test_privilege_escalation(
                    self.target_url, admin_paths
                ),
                timeout=15,
            )
            count = 0
            for pf in privesc_findings:
                raw = RawFinding(
                    test_id="PRIVESC-AUTH",
                    owasp_category="A01",
                    title=f"[Auth] Privilege Escalation — Path Accessible: {pf['path']}",
                    description=(
                        f"Authenticated as regular user '{self._auth_config.username}', "
                        f"admin path '{pf['path']}' returned HTTP {pf['status']} with "
                        f"{pf['size']} bytes. Horizontal or vertical privilege escalation confirmed."
                    ),
                    severity=Severity.CRITICAL,
                    url=pf["url"],
                    parameter=None,
                    evidence={
                        "auth_user": self._auth_config.username,
                        "admin_path": pf["path"],
                        "response_status": pf["status"],
                        "response_size": pf["size"],
                        "evidence": pf["evidence"],
                    },
                    remediation=(
                        "Implement role-based access control on all admin endpoints. "
                        "Verify user permissions server-side on every request."
                    ),
                    confidence=0.90,
                    cwe="CWE-269",
                    references=["https://owasp.org/A01_2021-Broken_Access_Control/"],
                )
                self._findings.append(raw)
                count += 1
            if count:
                await self._log("WARN",
                                f"Privilege escalation: {count} admin paths accessible as regular user",
                                progress=95)
            else:
                await self._log("INFO", "No privilege escalation found", progress=95)
        except asyncio.TimeoutError:
            await self._log("WARN", "Privilege escalation test timed out")
        except Exception as e:
            logger.warning(f"Privesc phase error: {e}")

    async def _header_phase(self) -> None:
        await self._log("SCAN", "Analysing HTTP security headers…", url=self.target_url, progress=6)
        try:
            t0   = time.time()
            resp = await self._client.get(self.target_url)
            ms   = int((time.time() - t0) * 1000)
            evidence = self._capture_http_evidence(self.target_url, resp, ms)
            self._http_evidence[self.target_url] = evidence
            try:
                req_hdrs = dict(resp.request.headers)
            except Exception:
                req_hdrs = {}
            self._traffic.record("GET", self.target_url, req_hdrs, {}, resp, ms)
            ctx = ScanContext(url=self.target_url, method="GET", response=resp, params={}, scan_id=self.scan_id)
            for mod in self._modules:
                if hasattr(mod, "analyze_headers"):
                    hits = await mod.analyze_headers(ctx)
                    for h in hits:
                        # Attach raw HTTP evidence to finding
                        h.evidence["http_evidence"] = evidence
                        await self._log(
                            "WARN" if h.severity in (Severity.HIGH, Severity.CRITICAL) else "INFO",
                            f"[{h.owasp_category}] {h.title}", url=self.target_url,
                        )
                    self._findings.extend(hits)
        except Exception as e:
            logger.warning(f"Header phase error: {e}")

    async def _sast_phase(self) -> None:
        await self._log("SCAN", "Running SAST header analysis…", url=self.target_url, progress=12)
        try:
            from app.scanner.sast_scanner import SASTScanner
            sast = SASTScanner(timeout=10)
            sast_findings = await sast.scan_target_headers(self.target_url, self._client)
            evidence_base = self._http_evidence.get(self.target_url, {})
            for sf in sast_findings:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                sev = sev_map.get(sf.severity, Severity.INFO)
                raw = RawFinding(
                    owasp_category=sf.category,
                    owasp_name="Security Misconfiguration",
                    title=f"[SAST] {sf.title}",
                    description=sf.description,
                    severity=sev,
                    affected_url=sf.file_path,
                    evidence={
                        "rule_id": sf.rule_id,
                        "snippet": sf.code_snippet,
                        "cwe": sf.cwe,
                        "http_evidence": evidence_base,
                    },
                    remediation=sf.remediation,
                    references=sf.references,
                    confidence=sf.confidence,
                    severity_weight={"critical":9,"high":7,"medium":5,"low":3,"info":1}.get(sf.severity, 3),
                )
                self._findings.append(raw)
                await self._log("INFO", f"[SAST] {sf.title}", url=self.target_url)
            await self._log("INFO", f"SAST phase complete: {len(sast_findings)} issues", progress=16)
        except Exception as e:
            logger.warning(f"SAST phase error: {e}")

    async def _crawl_phase(self) -> None:
        sem     = asyncio.Semaphore(4)
        crawled = 0
        max_u   = min(settings.SCAN_MAX_URLS, 30)
        while not self._queue.empty() and len(self._visited) < max_u and not self._timed_out():
            url, depth = await self._queue.get()
            if url in self._visited or depth > min(settings.SCAN_CRAWL_DEPTH, 3):
                continue
            if not self._in_scope(url):
                continue
            self._visited.add(url)
            crawled += 1
            progress = 20 + min(60, (crawled / max(max_u * 0.35, 1)) * 60)
            async with sem:
                await self._scan_url(url, depth, progress)
            await asyncio.sleep(0.05)

    async def _scan_url(self, url: str, depth: int, progress: float) -> None:
        if self._timed_out():
            return
        await self._log("SCAN", f"GET {url}", url=url, progress=progress)
        t0   = time.time()
        resp = await self._safe_get(url)
        if not resp:
            return
        ms   = int((time.time() - t0) * 1000)
        self._total_requests += 1

        # Capture raw HTTP evidence for this URL
        evidence = self._capture_http_evidence(url, resp, ms)
        self._http_evidence[url] = evidence

        params = self._extract_params(url, resp)
        try:
            req_hdrs = dict(resp.request.headers)
        except Exception:
            req_hdrs = {}
        record = self._traffic.record("GET", url, req_hdrs, params, resp, ms)

        await self._log(
            "OK" if resp.status_code < 300 else "WARN",
            f"Response {resp.status_code} ({ms}ms) — {len(resp.text):,} bytes",
            url=url, progress=progress,
        )
        if record.anomaly_flags:
            await self._log("WARN", f"Anomalies: {', '.join(record.anomaly_flags[:3])}", url=url)

        if depth < 3 and "text" in resp.headers.get("content-type", ""):
            for link in self._extract_links(url, resp.text):
                if link not in self._visited:
                    await self._queue.put((link, depth + 1))

        ctx = ScanContext(url=url, method="GET", response=resp, params=params, scan_id=self.scan_id, depth=depth)
        for mod in self._modules:
            if self._timed_out():
                break
            try:
                hits = await asyncio.wait_for(mod.analyze(ctx, self._client), timeout=5)
                for h in hits:
                    # Attach raw HTTP evidence to every finding
                    h.evidence["http_evidence"] = evidence
                    h.evidence["cvss_vector"]   = _cvss_vector(h.owasp_category, h.severity.value if hasattr(h.severity, "value") else str(h.severity))
                    lvl = "CRIT" if h.severity == Severity.CRITICAL else "WARN" if h.severity == Severity.HIGH else "INFO"
                    await self._log(lvl, f"[{h.owasp_category}] {h.title} (conf:{h.confidence:.0%})", url=url, progress=progress)
                self._findings.extend(hits)
            except asyncio.TimeoutError:
                logger.debug(f"Module {mod.module_id} timed out on {url}")
            except Exception as e:
                logger.debug(f"Module {mod.module_id} error on {url}: {e}")

    async def _post_crawl(self) -> None:
        await self._log("INFO", f"Post-crawl — {len(self._visited)} URLs visited", progress=84)
        s = self._traffic.get_summary()
        await self._log("INFO",
            f"Traffic: {s['total_requests']} reqs | {s['error_responses']} errors | {s['anomalous_responses']} anomalies",
            progress=87,
        )
        for ep in self._traffic.get_high_risk_endpoints()[:3]:
            await self._log("WARN", f"High-risk endpoint: {ep['endpoint']} (score {ep['risk_score']})")

    async def _finalize(self) -> None:
        await self._log("INFO", "Deduplicating and scoring findings…", progress=91)

        seen: set = set()
        unique: List[RawFinding] = []
        for f in self._findings:
            key = (f.owasp_category, f.affected_url, f.title)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        await self._log("INFO", f"{len(unique)} unique findings ({len(self._findings)-len(unique)} dupes removed)", progress=93)

        counts = {s: 0 for s in ["critical","high","medium","low","info"]}
        db_findings: List[Finding] = []

        for raw in unique:
            sev_str  = raw.severity.value if hasattr(raw.severity, "value") else str(raw.severity).lower()
            risk     = round(raw.severity_weight * raw.confidence * raw.exposure, 2)
            cvss     = _cvss_score(raw.owasp_category, sev_str)
            counts[sev_str] = counts.get(sev_str, 0) + 1

            # Ensure CVSS vector is in evidence
            if "cvss_vector" not in raw.evidence:
                raw.evidence["cvss_vector"] = _cvss_vector(raw.owasp_category, sev_str)
            raw.evidence["cvss_score"] = cvss

            db_findings.append(Finding(
                scan_id=self.scan_id, org_id=self.scan.org_id,
                owasp_category=raw.owasp_category, owasp_name=raw.owasp_name,
                title=raw.title, description=raw.description,
                severity=raw.severity,
                affected_url=raw.affected_url, affected_parameter=raw.affected_parameter,
                http_method=raw.http_method,
                severity_weight=raw.severity_weight, confidence=raw.confidence,
                exposure=raw.exposure, risk_score=risk,
                cvss_score=cvss,
                evidence=raw.evidence, remediation=raw.remediation, references=raw.references,
            ))

        for f in db_findings:
            self.db.add(f)

        high_scores  = [f.cvss_score for f in db_findings if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.cvss_score]
        overall_risk = round(max(high_scores) if high_scores else 0.0, 1)
        duration     = round(time.time() - self._start_time)

        self.scan.status         = ScanStatus.COMPLETED
        self.scan.completed_at   = datetime.now(timezone.utc)
        self.scan.progress       = 100.0
        self.scan.urls_crawled   = len(self._visited)
        self.scan.total_requests = self._total_requests
        self.scan.risk_score     = overall_risk
        self.scan.critical_count = counts["critical"]
        self.scan.high_count     = counts["high"]
        self.scan.medium_count   = counts["medium"]
        self.scan.low_count      = counts["low"]
        self.scan.info_count     = counts["info"]
        await self.db.commit()

        total = sum(counts.values())
        await self._log("OK",
            f"Scan complete — {total} findings | "
            f"Crit:{counts['critical']} High:{counts['high']} Med:{counts['medium']} Low:{counts['low']} | "
            f"Risk:{overall_risk}/10 | {duration}s",
            progress=100,
        )
        await websocket_manager.emit_scan_event(self.scan_id, "scan_complete", {
            "total": total, "counts": counts, "risk_score": overall_risk, "duration_seconds": duration,
        })
        await websocket_manager.emit_scan_event(self.scan_id, "progress_update", {"progress": 100})

        # ML: retrain on real findings — never breaks the scan
        try:
            from app.ml.severity_predictor import retrain_on_findings
            findings_for_ml = [
                {
                    "owasp_category": f.owasp_category,
                    "confidence": f.confidence,
                    "cvss_score": f.cvss_score,
                    "risk_score": f.risk_score,
                    "http_method": f.http_method,
                    "affected_parameter": f.affected_parameter,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                }
                for f in db_findings
            ]
            retrain_on_findings(findings_for_ml)
        except Exception:
            pass

    async def _safe_get(self, url: str) -> Optional[httpx.Response]:
        try:
            return await self._client.get(url)
        except Exception as e:
            logger.debug(f"GET {url} failed: {e}")
            return None

    def _in_scope(self, url: str) -> bool:
        try:
            p = urlparse(url)
            return (p.netloc == self.target_domain or p.netloc.endswith(f".{self.target_domain}"))
        except Exception:
            return False

    def _extract_links(self, base: str, html: str) -> List[str]:
        links: List[str] = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for tag in soup.find_all(["a","form","script","link","iframe"]):
                href = tag.get("href") or tag.get("src") or tag.get("action","")
                if href and not href.startswith(("javascript:","mailto:","#","data:")):
                    full = urljoin(base, href).split("#")[0]
                    if self._in_scope(full):
                        links.append(full)
        except Exception:
            pass
        return list(dict.fromkeys(links))[:20]

    def _extract_params(self, url: str, resp: httpx.Response) -> Dict[str, str]:
        params: Dict[str, str] = {}
        try:
            parsed = urlparse(url)
            if parsed.query:
                params.update({k: v[0] for k, v in parse_qs(parsed.query).items()})
            if "text/html" in resp.headers.get("content-type",""):
                soup = BeautifulSoup(resp.text, "html.parser")
                for inp in soup.find_all(["input","textarea","select"]):
                    name = inp.get("name")
                    if name:
                        params[name] = inp.get("value","")
        except Exception:
            pass
        return params

    async def _set_status(self, status: ScanStatus, error: str = None) -> None:
        self.scan.status = status
        if error:
            self.scan.error_message = error
        if status == ScanStatus.RUNNING:
            self.scan.started_at = datetime.now(timezone.utc)
        await self.db.commit()

    async def _log(self, level: str, message: str, url: str = None, progress: float = None) -> None:
        entry = ScanLogEntry(level=level, message=message, scan_id=self.scan_id, url=url, progress=progress)
        await websocket_manager.emit_log(entry)
        if progress is not None:
            self.scan.progress = progress
        logger.info(f"[{self.scan_id[:8]}][{level}] {message}")
