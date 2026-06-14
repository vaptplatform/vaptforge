"""
VAPTForge Authenticated Scanner
Handles login, session maintenance, and post-auth scanning.
Supports: form-based login, Bearer token, Basic auth, API key header.
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("vapt.auth_scanner")


@dataclass
class AuthConfig:
    """Authentication configuration supplied by user."""
    auth_type: str = "none"          # none | form | bearer | basic | apikey
    login_url: str = ""
    username: str = ""
    password: str = ""
    username_field: str = "username" # form field name for username
    password_field: str = "password" # form field name for password
    token: str = ""                  # for bearer/apikey
    api_key_header: str = "X-API-Key"
    success_indicator: str = ""      # text in response that confirms login success
    logout_indicator: str = "logout" # text that confirms we're still logged in

    @classmethod
    def from_scan_options(cls, options: dict) -> "AuthConfig":
        auth = options.get("auth", {})
        return cls(
            auth_type        = auth.get("auth_type", "none"),
            login_url        = auth.get("login_url", ""),
            username         = auth.get("username", ""),
            password         = auth.get("password", ""),
            username_field   = auth.get("username_field", "username"),
            password_field   = auth.get("password_field", "password"),
            token            = auth.get("token", ""),
            api_key_header   = auth.get("api_key_header", "X-API-Key"),
            success_indicator= auth.get("success_indicator", ""),
            logout_indicator = auth.get("logout_indicator", "logout"),
        )

    @property
    def is_enabled(self) -> bool:
        return self.auth_type != "none"


@dataclass
class AuthResult:
    success: bool
    method: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_token: str = ""
    error: str = ""
    evidence: str = ""


class AuthenticatedScanner:
    """
    Handles authentication before scanning and maintains session throughout.
    """

    def __init__(self, config: AuthConfig, base_client: httpx.AsyncClient):
        self.config = config
        self.client = base_client
        self._auth_headers: Dict[str, str] = {}
        self._auth_cookies: Dict[str, str] = {}
        self._logged_in = False

    async def authenticate(self, target_url: str) -> AuthResult:
        """Perform authentication based on config type."""
        if not self.config.is_enabled:
            return AuthResult(success=False, method="none", error="No auth configured")

        method = self.config.auth_type
        logger.info(f"Attempting {method} authentication for {target_url}")

        if method == "bearer":
            return await self._auth_bearer()
        elif method == "basic":
            return await self._auth_basic()
        elif method == "apikey":
            return await self._auth_apikey()
        elif method == "form":
            return await self._auth_form(target_url)
        else:
            return AuthResult(success=False, method=method, error=f"Unknown auth type: {method}")

    async def _auth_bearer(self) -> AuthResult:
        """Set Bearer token authentication."""
        if not self.config.token:
            return AuthResult(success=False, method="bearer", error="No token provided")
        self._auth_headers["Authorization"] = f"Bearer {self.config.token}"
        self._logged_in = True
        return AuthResult(
            success=True, method="bearer",
            headers={"Authorization": f"Bearer {self.config.token}"},
            evidence=f"Bearer token set: {self.config.token[:20]}...",
        )

    async def _auth_basic(self) -> AuthResult:
        """Set HTTP Basic authentication."""
        import base64
        if not self.config.username or not self.config.password:
            return AuthResult(success=False, method="basic", error="Username/password required")
        creds = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode()
        ).decode()
        self._auth_headers["Authorization"] = f"Basic {creds}"
        self._logged_in = True
        return AuthResult(
            success=True, method="basic",
            headers={"Authorization": f"Basic {creds}"},
            evidence=f"Basic auth set for user: {self.config.username}",
        )

    async def _auth_apikey(self) -> AuthResult:
        """Set API key header authentication."""
        if not self.config.token:
            return AuthResult(success=False, method="apikey", error="No API key provided")
        self._auth_headers[self.config.api_key_header] = self.config.token
        self._logged_in = True
        return AuthResult(
            success=True, method="apikey",
            headers={self.config.api_key_header: self.config.token},
            evidence=f"API key set in header: {self.config.api_key_header}",
        )

    async def _auth_form(self, target_url: str) -> AuthResult:
        """Perform form-based login."""
        if not self.config.username or not self.config.password:
            return AuthResult(success=False, method="form", error="Username/password required")

        login_url = self.config.login_url
        if not login_url:
            # Auto-detect login URL
            login_url = await self._find_login_url(target_url)
        if not login_url:
            return AuthResult(success=False, method="form", error="Could not find login URL")

        try:
            # Fetch login page to get CSRF token
            login_page = await asyncio.wait_for(self.client.get(login_url), timeout=10)
            csrf_token = self._extract_csrf(login_page.text)

            # Build form data
            form_data = {
                self.config.username_field: self.config.username,
                self.config.password_field: self.config.password,
            }
            if csrf_token:
                # Try common CSRF field names
                for csrf_field in ["csrfmiddlewaretoken", "csrf_token", "_token",
                                    "authenticity_token", "csrf", "_csrf"]:
                    form_data[csrf_field] = csrf_token

            # Detect form action
            soup = BeautifulSoup(login_page.text, "html.parser")
            form = soup.find("form")
            if form and form.get("action"):
                action = urljoin(login_url, form.get("action"))
            else:
                action = login_url

            # Submit login
            resp = await asyncio.wait_for(
                self.client.post(action, data=form_data, follow_redirects=True),
                timeout=12
            )

            # Check success
            success = self._check_login_success(resp, login_url)
            if success:
                # Capture session cookies
                cookies = dict(self.client.cookies)
                self._auth_cookies = cookies

                # Check for token in response
                token = self._extract_token_from_response(resp)
                if token:
                    self._auth_headers["Authorization"] = f"Bearer {token}"

                self._logged_in = True
                logger.info(f"Form login successful for {self.config.username} at {login_url}")
                return AuthResult(
                    success=True, method="form",
                    cookies=cookies,
                    headers=self._auth_headers,
                    session_token=token or "",
                    evidence=(
                        f"POST {action}\n"
                        f"Fields: {self.config.username_field}={self.config.username}, "
                        f"{self.config.password_field}=***\n"
                        f"Response: HTTP {resp.status_code} | "
                        f"Cookies: {list(cookies.keys())}"
                    ),
                )
            else:
                return AuthResult(
                    success=False, method="form",
                    error=f"Login failed — HTTP {resp.status_code}. "
                          f"Check credentials and login URL.",
                    evidence=f"POST {action} → HTTP {resp.status_code}\n"
                             f"Response size: {len(resp.text)} bytes",
                )

        except asyncio.TimeoutError:
            return AuthResult(success=False, method="form", error="Login request timed out")
        except Exception as e:
            logger.error(f"Form auth error: {e}")
            return AuthResult(success=False, method="form", error=str(e))

    async def _find_login_url(self, target_url: str) -> Optional[str]:
        """Auto-discover login URL from target."""
        parsed = urlparse(target_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        common_paths = [
            "/login", "/signin", "/auth/login", "/user/login",
            "/account/login", "/api/login", "/api/auth/login",
            "/admin/login", "/portal/login",
        ]
        for path in common_paths:
            url = base + path
            try:
                resp = await asyncio.wait_for(self.client.get(url), timeout=6)
                if resp.status_code == 200 and any(
                    kw in resp.text.lower()
                    for kw in ["password", "login", "signin", "username", "email"]
                ):
                    logger.info(f"Auto-detected login URL: {url}")
                    return url
            except Exception:
                pass
        return None

    def _extract_csrf(self, html: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        # Common CSRF input names
        for name in ["csrfmiddlewaretoken", "csrf_token", "_token",
                      "authenticity_token", "csrf", "_csrf"]:
            inp = soup.find("input", {"name": name})
            if inp and inp.get("value"):
                return inp["value"]
        # Meta tag CSRF
        meta = soup.find("meta", {"name": re.compile(r"csrf", re.I)})
        if meta and meta.get("content"):
            return meta["content"]
        return None

    def _check_login_success(self, resp: httpx.Response, login_url: str) -> bool:
        """Check if login was successful."""
        # User-specified indicator
        if self.config.success_indicator:
            return self.config.success_indicator.lower() in resp.text.lower()
        # Redirected away from login page = success
        if str(resp.url) != login_url and resp.status_code in (200, 302):
            return True
        # Common success indicators
        body = resp.text.lower()
        success_signs = ["dashboard", "welcome", "logout", "profile",
                          "account", "my account", "sign out"]
        fail_signs    = ["invalid", "incorrect", "failed", "error",
                          "wrong password", "login failed", "unauthorized"]
        has_success = any(s in body for s in success_signs)
        has_fail    = any(f in body for f in fail_signs)
        return has_success and not has_fail

    def _extract_token_from_response(self, resp: httpx.Response) -> Optional[str]:
        """Extract JWT/Bearer token from login response."""
        try:
            data = resp.json()
            for key in ["token", "access_token", "accessToken", "jwt",
                          "auth_token", "authToken", "id_token"]:
                if key in data:
                    return str(data[key])
                if "data" in data and isinstance(data["data"], dict):
                    if key in data["data"]:
                        return str(data["data"][key])
        except Exception:
            pass
        # Try regex in response body
        jwt_pattern = r'["\'](?:token|access_token|jwt)["\']:\s*["\']([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)["\']'
        match = re.search(jwt_pattern, resp.text)
        if match:
            return match.group(1)
        return None

    def get_auth_headers(self) -> Dict[str, str]:
        return dict(self._auth_headers)

    def get_auth_cookies(self) -> Dict[str, str]:
        return dict(self._auth_cookies)

    @property
    def is_authenticated(self) -> bool:
        return self._logged_in

    async def verify_session_alive(self, target_url: str) -> bool:
        """Check if the session is still valid."""
        try:
            resp = await asyncio.wait_for(self.client.get(target_url), timeout=8)
            body = resp.text.lower()
            # If we get redirected to login, session died
            if "login" in str(resp.url).lower():
                return False
            if self.config.logout_indicator:
                return self.config.logout_indicator.lower() in body
            return resp.status_code == 200
        except Exception:
            return False

    async def test_privilege_escalation(
        self, target_url: str, admin_paths: List[str]
    ) -> List[dict]:
        """
        After authenticating as regular user, test if admin paths are accessible.
        This is a real privilege escalation / IDOR test.
        """
        findings = []
        parsed   = urlparse(target_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"

        for path in admin_paths[:10]:
            url = base.rstrip("/") + path
            try:
                resp = await asyncio.wait_for(self.client.get(url), timeout=6)
                if resp.status_code == 200 and len(resp.text) > 100:
                    body = resp.text.lower()
                    admin_indicators = [
                        "admin", "dashboard", "manage", "users", "settings",
                        "config", "system", "control"
                    ]
                    if any(ind in body for ind in admin_indicators):
                        findings.append({
                            "path": path,
                            "url": url,
                            "status": resp.status_code,
                            "size": len(resp.text),
                            "type": "privilege_escalation",
                            "evidence": (
                                f"Authenticated as regular user '{self.config.username}', "
                                f"accessed admin path '{path}' → HTTP {resp.status_code}"
                            ),
                        })
            except Exception:
                pass
        return findings
