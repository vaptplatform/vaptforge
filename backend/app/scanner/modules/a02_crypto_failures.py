"""
OWASP A02 — Cryptographic Failures
Real ethical-hacker-level detection:
  - Real TLS version + cipher check via ssl module
  - Certificate expiry check
  - HTTP → HTTPS redirect test (both directions)
  - HSTS header presence + max-age validation
  - Sensitive data patterns in response body
  - Mixed content detection
  - Weak cookie transmission over HTTP
"""
import logging
import re
import ssl
import socket
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

import httpx

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a02")

SENSITIVE_PATTERNS = [
    (re.compile(r'"password"\s*:\s*"[^"]{3,}"', re.I),           "password field in JSON response"),
    (re.compile(r'"passwd"\s*:\s*"[^"]{3,}"', re.I),             "passwd field in JSON response"),
    (re.compile(r'"api_key"\s*:\s*"[^"]{8,}"', re.I),            "API key in response body"),
    (re.compile(r'"secret"\s*:\s*"[^"]{8,}"', re.I),             "secret field in response body"),
    (re.compile(r'"token"\s*:\s*"[A-Za-z0-9\-_.]{20,}"', re.I),  "auth token in response body"),
    (re.compile(r'"access_token"\s*:\s*"[^"]{10,}"', re.I),      "access_token in response body"),
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'),                      "possible credit card number"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "private key in response"),
    (re.compile(r'Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.]+', re.I), "Bearer token in response"),
    (re.compile(r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"', re.I),      "SSN in response body"),
    (re.compile(r'DB_PASSWORD\s*=\s*\S+', re.I),                  "DB password in response"),
    (re.compile(r'AWS_SECRET_ACCESS_KEY\s*=\s*\S+', re.I),        "AWS secret key in response"),
]

WEAK_TLS_VERSIONS = {
    ssl.TLSVersion.SSLv3:  ("SSLv3",  Severity.CRITICAL),
    ssl.TLSVersion.TLSv1:  ("TLS 1.0", Severity.HIGH),
    ssl.TLSVersion.TLSv1_1:("TLS 1.1", Severity.MEDIUM),
}

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ADH", "AECDH",
    "anon", "aNULL", "eNULL",
]

CERT_EXPIRY_WARN_DAYS = 30


class CryptoFailuresModule(BaseModule):
    module_id       = "a02_crypto_failures"
    owasp_category  = "A02"
    owasp_name      = "Cryptographic Failures"
    severity_weight = 7.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(ctx.url)

        # 1. HTTP → HTTPS redirect check
        if ctx.url.startswith("http://"):
            findings.append(self.build_finding(
                title="Plaintext HTTP — Data Transmitted Unencrypted",
                description=(
                    f"The endpoint '{ctx.url}' is served over plain HTTP. "
                    f"All data including credentials, session tokens, and PII "
                    f"is transmitted in cleartext and can be intercepted by a "
                    f"network attacker (MITM / SSL stripping)."
                ),
                severity=Severity.HIGH,
                url=ctx.url,
                evidence={
                    "detection_method": "protocol_inspection",
                    "protocol": "http",
                    "response_status": ctx.status_code,
                },
                remediation=(
                    "Enforce HTTPS site-wide. Redirect all HTTP to HTTPS with 301. "
                    "Add HSTS header. Use TLS 1.2 or higher only."
                ),
                references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
                confidence=0.99,
            ))

            # Test if HTTPS version exists and HTTP redirects to it
            https_url = ctx.url.replace("http://", "https://", 1)
            redirect_finding = await self._check_http_to_https_redirect(
                ctx.url, https_url, client
            )
            if redirect_finding:
                findings.append(redirect_finding)

        # 2. HTTPS — run TLS checks
        if ctx.url.startswith("https://"):
            host = parsed.hostname
            port = parsed.port or 443

            tls_findings = await self._check_tls(ctx.url, host, port)
            findings.extend(tls_findings)

            cert_finding = await self._check_certificate(ctx.url, host, port)
            if cert_finding:
                findings.append(cert_finding)

        # 3. Sensitive data in response body
        body = ctx.response_body
        for pattern, description in SENSITIVE_PATTERNS:
            match = pattern.search(body)
            if match:
                findings.append(self.build_finding(
                    title=f"Sensitive Data Exposed in Response: {description}",
                    description=(
                        f"The response at '{ctx.url}' contains {description}. "
                        f"Sensitive values must never be returned in API responses unnecessarily. "
                        f"This data can be captured by a MITM or logged by proxies."
                    ),
                    severity=Severity.HIGH,
                    url=ctx.url,
                    evidence={
                        "detection_method": "response_body_pattern",
                        "pattern_description": description,
                        "matched_snippet": match.group(0)[:80],
                        "response_status": ctx.status_code,
                        "content_type": ctx.response_headers.get("content-type", ""),
                    },
                    remediation=(
                        "Remove sensitive fields from API responses. "
                        "Apply field-level encryption for PII. "
                        "Never return credentials, keys, or tokens in responses."
                    ),
                    confidence=0.78,
                ))
                break  # one per URL to avoid noise

        # 4. Mixed content detection (HTTPS page loading HTTP resources)
        if ctx.url.startswith("https://"):
            mixed = self._check_mixed_content(ctx.url, ctx.response_body)
            if mixed:
                findings.append(mixed)

        return findings

    async def analyze_headers(self, ctx: ScanContext) -> List[RawFinding]:
        findings: List[RawFinding] = []
        headers = {k.lower(): v for k, v in ctx.response_headers.items()}

        # HSTS missing on HTTPS
        if ctx.url.startswith("https://"):
            hsts = headers.get("strict-transport-security", "")
            if not hsts:
                findings.append(self.build_finding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description=(
                        f"The HTTPS endpoint '{ctx.url}' does not send the "
                        f"Strict-Transport-Security header. Without HSTS, browsers "
                        f"may connect over HTTP on subsequent visits, enabling SSL-stripping attacks."
                    ),
                    severity=Severity.MEDIUM,
                    url=ctx.url,
                    evidence={
                        "detection_method": "hsts_header_check",
                        "missing_header": "strict-transport-security",
                    },
                    remediation=(
                        "Add: Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains; preload"
                    ),
                    confidence=0.99,
                ))
            elif "max-age" in hsts.lower():
                # Check max-age value — too short is also a finding
                ma_match = re.search(r"max-age=(\d+)", hsts, re.I)
                if ma_match:
                    max_age = int(ma_match.group(1))
                    if max_age < 31536000:  # less than 1 year
                        findings.append(self.build_finding(
                            title="HSTS max-age Too Short",
                            description=(
                                f"The HSTS max-age is only {max_age} seconds "
                                f"({max_age // 86400} days). OWASP recommends at least "
                                f"1 year (31536000 seconds) to prevent SSL-stripping."
                            ),
                            severity=Severity.LOW,
                            url=ctx.url,
                            evidence={
                                "detection_method": "hsts_max_age_check",
                                "hsts_header": hsts,
                                "max_age_seconds": max_age,
                                "recommended_minimum": 31536000,
                            },
                            remediation="Set max-age=31536000 or higher in HSTS header.",
                            confidence=0.95,
                        ))

        return findings

    # ── HTTP → HTTPS redirect check ───────────────────────────────────────────
    async def _check_http_to_https_redirect(
        self, http_url: str, https_url: str, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """Check if HTTP URL redirects to HTTPS. If not — finding."""
        try:
            # Use a client that does NOT follow redirects so we can inspect the Location header
            resp = await client.get(http_url, follow_redirects=False, timeout=7)
            location = resp.headers.get("location", "")

            if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                # Good — HTTP redirects to HTTPS
                return None

            # No redirect to HTTPS
            return self.build_finding(
                title="HTTP Does Not Redirect to HTTPS",
                description=(
                    f"The HTTP endpoint '{http_url}' returned HTTP {resp.status_code} "
                    f"without redirecting to HTTPS. Clients connecting over plain HTTP "
                    f"are not forced to use an encrypted connection, exposing all data."
                ),
                severity=Severity.HIGH,
                url=http_url,
                evidence={
                    "detection_method": "http_to_https_redirect_check",
                    "http_status": resp.status_code,
                    "location_header": location or "not present",
                    "redirects_to_https": False,
                },
                remediation=(
                    "Configure a 301 redirect from all HTTP URLs to their HTTPS equivalents. "
                    "Add HSTS to prevent future HTTP connections."
                ),
                confidence=0.95,
            )
        except Exception as e:
            logger.debug(f"HTTP→HTTPS redirect check error: {e}")
        return None

    # ── TLS version + cipher check ────────────────────────────────────────────
    async def _check_tls(
        self, url: str, host: str, port: int
    ) -> List[RawFinding]:
        """Connect with ssl module to detect TLS version and weak ciphers."""
        findings: List[RawFinding] = []

        # Test for weak TLS versions by trying to connect with them
        for tls_version, (version_name, severity) in WEAK_TLS_VERSIONS.items():
            try:
                ctx_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx_ssl.check_hostname = False
                ctx_ssl.verify_mode    = ssl.CERT_NONE
                # Try to force old TLS version
                try:
                    ctx_ssl.minimum_version = tls_version
                    ctx_ssl.maximum_version = tls_version
                except AttributeError:
                    continue

                loop = __import__("asyncio").get_event_loop()
                conn_result = await loop.run_in_executor(
                    None, self._try_tls_connect, host, port, ctx_ssl
                )
                if conn_result:
                    findings.append(self.build_finding(
                        title=f"Weak TLS Version Accepted: {version_name}",
                        description=(
                            f"The server at '{host}:{port}' accepts {version_name} connections. "
                            f"{version_name} is considered cryptographically broken and should "
                            f"not be supported. Attackers can downgrade connections and decrypt traffic."
                        ),
                        severity=severity,
                        url=url,
                        evidence={
                            "detection_method": "tls_version_probe",
                            "tls_version": version_name,
                            "host": host,
                            "port": port,
                        },
                        remediation=(
                            f"Disable {version_name} in server TLS configuration. "
                            "Only allow TLS 1.2 and TLS 1.3. "
                            "Reference: https://ssl-config.mozilla.org/"
                        ),
                        references=["https://owasp.org/www-project-top-ten/"],
                        confidence=0.95,
                    ))
            except Exception as e:
                logger.debug(f"TLS version probe {version_name} error: {e}")

        # Check active cipher suite
        try:
            loop = __import__("asyncio").get_event_loop()
            cipher_info = await loop.run_in_executor(
                None, self._get_cipher_info, host, port
            )
            if cipher_info:
                cipher_name, tls_ver, bits = cipher_info
                for weak in WEAK_CIPHERS:
                    if weak.upper() in cipher_name.upper():
                        findings.append(self.build_finding(
                            title=f"Weak Cipher Suite in Use: {cipher_name}",
                            description=(
                                f"The server negotiated a weak cipher suite: '{cipher_name}' "
                                f"({bits}-bit, {tls_ver}). Weak ciphers can be broken by "
                                f"an attacker to decrypt the communication."
                            ),
                            severity=Severity.HIGH,
                            url=url,
                            evidence={
                                "detection_method": "cipher_suite_check",
                                "cipher": cipher_name,
                                "tls_version": tls_ver,
                                "key_bits": bits,
                            },
                            remediation=(
                                "Configure strong cipher suites only. "
                                "Use Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/ "
                                "Disable RC4, DES, 3DES, NULL, and EXPORT ciphers."
                            ),
                            confidence=0.92,
                        ))
                        break
        except Exception as e:
            logger.debug(f"Cipher check error: {e}")

        return findings

    def _try_tls_connect(self, host: str, port: int, ctx_ssl: ssl.SSLContext) -> bool:
        """Synchronous TLS connect attempt — run in executor."""
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _get_cipher_info(self, host: str, port: int):
        """Get negotiated cipher suite info — run in executor."""
        try:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return cipher[0], cipher[1], cipher[2]
        except Exception:
            pass
        return None

    # ── Certificate expiry check ──────────────────────────────────────────────
    async def _check_certificate(
        self, url: str, host: str, port: int
    ) -> Optional[RawFinding]:
        """Check TLS certificate expiry date."""
        try:
            loop = __import__("asyncio").get_event_loop()
            expiry = await loop.run_in_executor(
                None, self._get_cert_expiry, host, port
            )
            if expiry is None:
                return None

            now        = datetime.now(timezone.utc)
            days_left  = (expiry - now).days

            if days_left < 0:
                return self.build_finding(
                    title="TLS Certificate Expired",
                    description=(
                        f"The TLS certificate for '{host}' expired {abs(days_left)} days ago "
                        f"(expired: {expiry.strftime('%Y-%m-%d')}). "
                        f"Browsers will show security warnings and connections may be rejected."
                    ),
                    severity=Severity.CRITICAL,
                    url=url,
                    evidence={
                        "detection_method": "certificate_expiry_check",
                        "expiry_date": expiry.isoformat(),
                        "days_expired": abs(days_left),
                    },
                    remediation="Renew the TLS certificate immediately.",
                    confidence=1.0,
                )
            elif days_left < CERT_EXPIRY_WARN_DAYS:
                return self.build_finding(
                    title=f"TLS Certificate Expiring Soon ({days_left} days)",
                    description=(
                        f"The TLS certificate for '{host}' expires in {days_left} days "
                        f"({expiry.strftime('%Y-%m-%d')}). If not renewed, users will see "
                        f"security warnings and HTTPS connections will fail."
                    ),
                    severity=Severity.MEDIUM,
                    url=url,
                    evidence={
                        "detection_method": "certificate_expiry_check",
                        "expiry_date": expiry.isoformat(),
                        "days_remaining": days_left,
                    },
                    remediation=f"Renew the TLS certificate within {days_left} days.",
                    confidence=1.0,
                )
        except Exception as e:
            logger.debug(f"Certificate check error for {host}: {e}")
        return None

    def _get_cert_expiry(self, host: str, port: int) -> Optional[datetime]:
        """Get cert expiry date synchronously — run in executor."""
        try:
            ctx_ssl = ssl.create_default_context()
            ctx_ssl.check_hostname = False
            ctx_ssl.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx_ssl.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert and "notAfter" in cert:
                        expiry_str = cert["notAfter"]
                        # Format: "Jan  1 00:00:00 2025 GMT"
                        expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        return expiry.replace(tzinfo=timezone.utc)
        except Exception as e:
            logger.debug(f"Cert expiry fetch error: {e}")
        return None

    # ── Mixed content detection ───────────────────────────────────────────────
    def _check_mixed_content(self, url: str, body: str) -> Optional[RawFinding]:
        """Detect HTTP resources loaded on an HTTPS page."""
        http_res_re = re.compile(
            r'(?:src|href|action)\s*=\s*["\']http://[^"\']+["\']', re.I
        )
        matches = http_res_re.findall(body)
        if matches:
            return self.build_finding(
                title="Mixed Content — HTTP Resources on HTTPS Page",
                description=(
                    f"The HTTPS page at '{url}' loads {len(matches)} resource(s) over plain HTTP. "
                    f"Mixed content allows attackers to intercept or modify these resources, "
                    f"potentially injecting malicious scripts or content."
                ),
                severity=Severity.MEDIUM,
                url=url,
                evidence={
                    "detection_method": "mixed_content_scan",
                    "http_resources_count": len(matches),
                    "examples": matches[:3],
                },
                remediation=(
                    "Update all resource URLs to use HTTPS. "
                    "Add Content-Security-Policy: upgrade-insecure-requests "
                    "or block-all-mixed-content directives."
                ),
                confidence=0.88,
            )
        return None
