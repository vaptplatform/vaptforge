"""
OWASP A04 — Insecure Design
Real ethical-hacker-level detection:
  - Real rate limit test: sends 10 rapid POST requests to auth endpoints
    and measures if responses differ (lockout, 429, CAPTCHA trigger)
  - Mass assignment probe: sends extra fields in POST and checks if accepted
  - Predictable resource location probe
  - Business logic: negative price / quantity parameter test
  - Account enumeration via response timing/content difference
"""
import asyncio
import logging
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a04")

SENSITIVE_PATHS = [
    "/backup", "/backup.zip", "/db.sql", "/.git",
    "/config.php.bak", "/database.sql", "/dump.sql",
    "/admin/export", "/export", "/data/export",
]

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit", "x-ratelimit-remaining", "retry-after",
    "x-rate-limit-limit", "ratelimit-limit", "x-ratelimit-reset",
]

AUTH_ENDPOINTS = [
    "/login", "/auth", "/signin", "/api/login",
    "/api/auth", "/api/v1/login", "/api/v1/auth",
    "/user/login", "/account/login", "/session",
]

# How many rapid requests to send for rate limit test
RATE_LIMIT_BURST = 10


class InsecureDesignModule(BaseModule):
    module_id      = "a04_insecure_design"
    owasp_category = "A04"
    owasp_name     = "Insecure Design"
    severity_weight = 6.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(ctx.url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        url_lower = ctx.url.lower()

        # 1. Real rate limit test on auth endpoints
        is_auth_ep = any(kw in url_lower for kw in AUTH_ENDPOINTS)
        if is_auth_ep:
            rate_finding = await self._real_rate_limit_test(ctx.url, client)
            if rate_finding:
                findings.append(rate_finding)
        else:
            # Also probe known auth paths from base
            for path in AUTH_ENDPOINTS[:5]:
                probe_url = urljoin(base, path)
                try:
                    probe_resp = await client.get(probe_url, timeout=5)
                    if probe_resp.status_code in (200, 405):
                        # Endpoint exists — test rate limiting
                        rate_finding = await self._real_rate_limit_test(probe_url, client)
                        if rate_finding:
                            findings.append(rate_finding)
                            break
                except Exception:
                    pass

        # 2. Account enumeration via response difference
        enum_finding = await self._check_account_enumeration(base, client)
        if enum_finding:
            findings.append(enum_finding)

        # 3. Sensitive backup / data files accessible
        for path in SENSITIVE_PATHS[:6]:
            try:
                resp = await client.get(urljoin(base, path), timeout=5)
                if resp.status_code == 200 and len(resp.text) > 20:
                    findings.append(self.build_finding(
                        title=f"Sensitive Backup/Data File Accessible: {path}",
                        description=(
                            f"The path '{path}' returned HTTP 200 with {len(resp.text)} bytes, "
                            f"possibly exposing database dumps, backup archives, or source code."
                        ),
                        severity=Severity.HIGH,
                        url=urljoin(base, path),
                        evidence={
                            "detection_method": "sensitive_path_probe",
                            "path": path,
                            "response_status": 200,
                            "response_size": len(resp.text),
                            "snippet": resp.text[:200],
                        },
                        remediation=(
                            "Remove backup/export files from web root. "
                            "Store backups outside the document root. "
                            "Block access via .htaccess / Nginx deny rules."
                        ),
                        confidence=0.82,
                    ))
            except Exception:
                pass

        # 4. Business logic — negative value parameter test
        neg_finding = await self._check_negative_values(ctx, client)
        if neg_finding:
            findings.append(neg_finding)

        # 5. Mass assignment probe
        mass_finding = await self._check_mass_assignment(ctx, client)
        if mass_finding:
            findings.append(mass_finding)

        return findings

    # ── Real Rate Limit Test ───────────────────────────────────────────────────
    async def _real_rate_limit_test(
        self, url: str, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        Send RATE_LIMIT_BURST rapid POST requests with wrong credentials.
        A secure app should:
          - Return 429 after N failures, OR
          - Return Retry-After / ratelimit headers, OR
          - Return CAPTCHA / lockout response
        If all responses are identical 200/401 with no lockout — no rate limiting.
        """
        fake_creds = {"username": "test_vapt_probe", "password": "wrongpassword_vapt123"}
        responses  = []
        status_codes = []
        t_start    = time.time()

        try:
            # Send burst of rapid requests
            tasks = [
                client.post(url, json=fake_creds, timeout=6)
                for _ in range(RATE_LIMIT_BURST)
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    continue
                status_codes.append(r.status_code)
                responses.append(r)

        except Exception as e:
            logger.debug(f"Rate limit test error for {url}: {e}")
            return None

        elapsed = time.time() - t_start

        if not status_codes:
            return None

        # Check if any 429 / lockout was triggered
        got_429       = any(s == 429 for s in status_codes)
        got_lockout   = any(
            "locked" in r.text.lower() or
            "too many" in r.text.lower() or
            "captcha" in r.text.lower() or
            "blocked" in r.text.lower()
            for r in responses if hasattr(r, "text")
        )
        has_rate_hdrs = any(
            h in (responses[0].headers if responses else {})
            for h in RATE_LIMIT_HEADERS
        )

        if got_429 or got_lockout or has_rate_hdrs:
            # Rate limiting IS in place — no finding
            logger.debug(f"Rate limiting detected at {url} — no finding")
            return None

        # All responses same status — no rate limiting detected
        unique_statuses = set(status_codes)
        return self.build_finding(
            title=f"No Rate Limiting on Authentication Endpoint: {url}",
            description=(
                f"Sent {len(status_codes)} rapid POST requests with invalid credentials "
                f"to '{url}' in {elapsed:.1f}s. "
                f"All returned status codes: {unique_statuses}. "
                f"No 429 response, no lockout message, no rate-limit headers detected. "
                f"An attacker can perform unlimited brute-force or credential stuffing attacks."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence={
                "detection_method": "real_rate_limit_burst_test",
                "requests_sent": len(status_codes),
                "elapsed_seconds": round(elapsed, 2),
                "status_codes_seen": list(unique_statuses),
                "got_429": got_429,
                "got_lockout_message": got_lockout,
                "rate_limit_headers_found": has_rate_hdrs,
                "rate_limit_headers_checked": RATE_LIMIT_HEADERS,
            },
            remediation=(
                "Implement rate limiting: max 5 failed attempts per IP per 15 minutes. "
                "Return HTTP 429 with Retry-After header after threshold. "
                "Add CAPTCHA after 3 failures. "
                "Use account lockout with exponential backoff. "
                "Consider IP-based and account-based throttling independently."
            ),
            references=[
                "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            ],
            confidence=0.88,
        )

    # ── Account Enumeration ────────────────────────────────────────────────────
    async def _check_account_enumeration(
        self, base: str, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        Send login requests with:
          (a) valid-looking username + wrong password
          (b) completely random nonexistent username + wrong password
        If responses differ in length or content → account enumeration possible.
        """
        login_url = urljoin(base, "/login")
        try:
            resp_existing = await client.post(
                login_url,
                json={"username": "admin", "password": "vapt_wrong_probe_xyz"},
                timeout=6,
            )
            await asyncio.sleep(0.3)
            resp_nonexist = await client.post(
                login_url,
                json={"username": "vapt_nonexistent_user_xyz123", "password": "vapt_wrong_probe_xyz"},
                timeout=6,
            )

            body_a = resp_existing.text.lower()
            body_b = resp_nonexist.text.lower()
            len_diff = abs(len(body_a) - len(body_b))

            # Different messages = enumeration possible
            invalid_user_hints = ["user not found", "no account", "username not found",
                                   "invalid username", "user does not exist"]
            invalid_pass_hints = ["wrong password", "incorrect password", "invalid password",
                                   "password is incorrect"]

            found_user_msg = any(h in body_a for h in invalid_pass_hints)
            found_nouser_msg = any(h in body_b for h in invalid_user_hints)

            if found_user_msg and found_nouser_msg:
                return self.build_finding(
                    title="Account Enumeration via Login Error Messages",
                    description=(
                        f"The login endpoint at '{login_url}' returns different error messages "
                        f"for valid vs invalid usernames. "
                        f"Existing user got: password-related error. "
                        f"Non-existing user got: user-not-found error. "
                        f"Attackers can enumerate valid usernames before brute-forcing passwords."
                    ),
                    severity=Severity.MEDIUM,
                    url=login_url,
                    evidence={
                        "detection_method": "account_enumeration_response_diff",
                        "valid_user_response_snippet": resp_existing.text[:150],
                        "invalid_user_response_snippet": resp_nonexist.text[:150],
                        "response_length_diff": len_diff,
                    },
                    remediation=(
                        "Return identical error messages for invalid username and invalid password: "
                        "'Invalid username or password.' "
                        "Use constant-time comparison. Apply same rate limiting to both cases."
                    ),
                    references=[
                        "https://owasp.org/www-community/attacks/Testing_for_User_Enumeration_and_Guessable_User_Account_(OWASP-AT-002)"
                    ],
                    confidence=0.82,
                )

            # Even if messages are same, large size difference is suspicious
            if len_diff > 200 and resp_existing.status_code != resp_nonexist.status_code:
                return self.build_finding(
                    title="Possible Account Enumeration via Response Difference",
                    description=(
                        f"Login responses differ significantly: "
                        f"status {resp_existing.status_code} vs {resp_nonexist.status_code}, "
                        f"size diff {len_diff} bytes. "
                        f"Different responses for valid vs invalid users enable account enumeration."
                    ),
                    severity=Severity.LOW,
                    url=login_url,
                    evidence={
                        "detection_method": "account_enumeration_status_diff",
                        "status_existing_user": resp_existing.status_code,
                        "status_nonexistent_user": resp_nonexist.status_code,
                        "size_diff_bytes": len_diff,
                    },
                    remediation="Return identical HTTP status and response body for all failed login attempts.",
                    confidence=0.60,
                )

        except Exception as e:
            logger.debug(f"Account enumeration check error: {e}")

        return None

    # ── Negative Value Business Logic ──────────────────────────────────────────
    async def _check_negative_values(
        self, ctx: ScanContext, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        If URL has price/amount/quantity/qty params, test negative values.
        A secure app should reject negative values.
        """
        from urllib.parse import parse_qs, urlencode, urlunparse
        parsed = urlparse(ctx.url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        numeric_business_params = [
            p for p in params
            if any(kw in p.lower() for kw in
                   ["price", "amount", "qty", "quantity", "total", "count", "num"])
        ]
        if not numeric_business_params:
            return None

        param = numeric_business_params[0]
        neg_params = {**params, param: "-1"}
        neg_url = urlunparse(parsed._replace(query=urlencode(neg_params)))

        try:
            resp = await client.get(neg_url, timeout=6)
            if resp.status_code == 200 and len(resp.text) > 50:
                body_lower = resp.text.lower()
                if not any(w in body_lower for w in
                           ["invalid", "error", "must be positive", "greater than", "negative"]):
                    return self.build_finding(
                        title=f"Business Logic Flaw — Negative Value Accepted: '{param}'",
                        description=(
                            f"Parameter '{param}' accepted a negative value (-1) at '{ctx.url}' "
                            f"without rejection. In e-commerce or financial applications this "
                            f"can allow price manipulation, negative charges, or free items."
                        ),
                        severity=Severity.HIGH,
                        url=neg_url,
                        parameter=param,
                        evidence={
                            "detection_method": "negative_value_probe",
                            "param": param,
                            "probe_value": "-1",
                            "response_status": resp.status_code,
                            "response_snippet": resp.text[:200],
                        },
                        remediation=(
                            "Validate all numeric inputs server-side: enforce minimum values. "
                            "Reject negative quantities, prices, or counts with 400 Bad Request. "
                            "Never trust client-supplied pricing or quantity data."
                        ),
                        confidence=0.70,
                    )
        except Exception as e:
            logger.debug(f"Negative value probe error: {e}")

        return None

    # ── Mass Assignment Probe ──────────────────────────────────────────────────
    async def _check_mass_assignment(
        self, ctx: ScanContext, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        Send POST with extra privileged fields (is_admin, role, verified).
        If server returns 200 and echoes back those fields — mass assignment possible.
        """
        url_lower = ctx.url.lower()
        is_reg_ep = any(kw in url_lower for kw in
                        ["/register", "/signup", "/user/create", "/api/users"])
        if not is_reg_ep:
            return None

        probe_payload = {
            "username":  "vapt_probe_user",
            "email":     "vapt_probe@example.com",
            "password":  "VaptProbe123!",
            "is_admin":  True,
            "role":      "admin",
            "verified":  True,
            "active":    True,
        }
        try:
            resp = await client.post(ctx.url, json=probe_payload, timeout=7)
            body_lower = resp.text.lower()

            if resp.status_code in (200, 201):
                echoed = [
                    f for f in ["is_admin", "role", "verified", "active"]
                    if f in body_lower and "true" in body_lower
                ]
                if echoed:
                    return self.build_finding(
                        title="Mass Assignment Vulnerability — Privileged Fields Accepted",
                        description=(
                            f"The endpoint '{ctx.url}' accepted privileged fields in the request body: "
                            f"{echoed}. The response echoed these values back, suggesting "
                            f"the server bound them directly to the model without filtering. "
                            f"An attacker can escalate privileges during registration."
                        ),
                        severity=Severity.CRITICAL,
                        url=ctx.url,
                        evidence={
                            "detection_method": "mass_assignment_probe",
                            "probe_payload": probe_payload,
                            "echoed_fields": echoed,
                            "response_status": resp.status_code,
                            "response_snippet": resp.text[:300],
                        },
                        remediation=(
                            "Use allowlists (not blocklists) for model binding. "
                            "Explicitly specify which fields can be set by users. "
                            "Never bind request body directly to DB model. "
                            "Use separate DTOs for user input vs internal models."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
                        ],
                        confidence=0.80,
                    )
        except Exception as e:
            logger.debug(f"Mass assignment probe error: {e}")

        return None
