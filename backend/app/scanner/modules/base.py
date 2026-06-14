"""
Base Module - Abstract base class for all OWASP detection modules
Defines the interface and shared utilities for safe, non-destructive vulnerability detection.
"""
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

from app.models.models import Severity


@dataclass
class ScanContext:
    """Encapsulates all data available to a module during analysis."""
    url: str
    method: str
    response: httpx.Response
    params: Dict[str, str]
    scan_id: str
    depth: int = 0
    request_headers: Dict[str, str] = field(default_factory=dict)
    extra: Dict = field(default_factory=dict)

    @property
    def response_body(self) -> str:
        try:
            return self.response.text
        except Exception:
            return ""

    @property
    def response_headers(self) -> Dict[str, str]:
        return dict(self.response.headers)

    @property
    def status_code(self) -> int:
        return self.response.status_code


@dataclass
class RawFinding:
    """Raw finding produced by a scanner module before DB persistence."""
    owasp_category: str        # e.g. "A03"
    owasp_name: str            # e.g. "Injection"
    title: str
    description: str
    severity: Severity
    affected_url: str
    affected_parameter: Optional[str] = None
    http_method: str = "GET"
    severity_weight: float = 5.0    # 1–10, OWASP-based
    confidence: float = 0.8          # 0.0–1.0
    exposure: float = 1.0            # 1.0=public, 0.6=internal
    evidence: Dict = field(default_factory=dict)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)


class BaseModule(ABC):
    """
    Abstract base class for all OWASP Top 10 detection modules.
    All detection is PASSIVE or uses safe reflection analysis only.
    NO exploit payloads. NO data modification.
    """

    module_id: str = "base"
    owasp_category: str = "A00"
    owasp_name: str = "Unknown"
    severity_weight: float = 5.0

    # Safe test strings that reveal vulnerability patterns without exploiting them
    # These trigger error messages or reflections but cause no harm
    SAFE_REFLECTION_PROBES = [
        "vapt'\"--",          # Triggers SQL parser errors if vulnerable (non-destructive)
        "<vapt>test</vapt>",  # Reveals XSS reflection without script execution
        "${vapt}",            # Template injection detection
        "/../vapt",           # Path traversal indicator
    ]

    # Error signatures that indicate SQL injection (pattern matching only)
    SQL_ERROR_PATTERNS = [
        re.compile(r"SQL syntax.*MySQL", re.I),
        re.compile(r"Warning.*mysql_", re.I),
        re.compile(r"ORA-\d{5}", re.I),
        re.compile(r"PG::SyntaxError", re.I),
        re.compile(r"SQLite3::Exception", re.I),
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"SQLSTATE\[", re.I),
        re.compile(r"sqlite_query\(\)", re.I),
        re.compile(r"Warning.*pg_query\(\)", re.I),
    ]

    # XSS reflection patterns
    XSS_REFLECTION_PATTERNS = [
        re.compile(r"<vapt>test</vapt>", re.I),
        re.compile(r"vapt'\"--", re.I),
    ]

    # Server error patterns (for A05 detection)
    ERROR_DISCLOSURE_PATTERNS = [
        re.compile(r"stack trace", re.I),
        re.compile(r"at com\.[a-z]+\.", re.I),
        re.compile(r"Exception in thread", re.I),
        re.compile(r"Traceback \(most recent call last\)", re.I),
        re.compile(r"Warning: .+\(\) expects", re.I),
        re.compile(r"Fatal error:", re.I),
        re.compile(r"Parse error:", re.I),
        re.compile(r"unhandled exception", re.I),
    ]

    @abstractmethod
    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        """
        Main analysis method.
        Must return a list of RawFinding objects.
        Must NOT perform destructive operations.
        Must NOT send data modification requests (only GET + safe observation).
        """
        pass

    async def analyze_headers(self, ctx: ScanContext) -> List[RawFinding]:
        """Optional: header-only analysis. Override in header-focused modules."""
        return []

    # ── Shared utilities ──────────────────────────────────────────────────────

    def check_sql_errors(self, body: str) -> Optional[str]:
        """Check response body for SQL error signatures."""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = pattern.search(body)
            if match:
                return match.group(0)[:200]
        return None

    def check_error_disclosure(self, body: str) -> Optional[str]:
        """Check for stack traces or verbose error messages."""
        for pattern in self.ERROR_DISCLOSURE_PATTERNS:
            match = pattern.search(body)
            if match:
                return match.group(0)[:200]
        return None

    def response_diff(self, body1: str, body2: str, threshold: float = 0.3) -> float:
        """
        Compute normalized difference ratio between two responses.
        Used for blind detection (comparing normal vs. probe responses).
        Returns 0.0 (identical) to 1.0 (completely different).
        """
        if not body1 and not body2:
            return 0.0
        if not body1 or not body2:
            return 1.0
        len1, len2 = len(body1), len(body2)
        ratio = abs(len1 - len2) / max(len1, len2)
        return ratio

    def build_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        url: str,
        parameter: str = None,
        evidence: dict = None,
        remediation: str = "",
        references: List[str] = None,
        confidence: float = 0.8,
        exposure: float = 1.0,
    ) -> RawFinding:
        return RawFinding(
            owasp_category=self.owasp_category,
            owasp_name=self.owasp_name,
            title=title,
            description=description,
            severity=severity,
            affected_url=url,
            affected_parameter=parameter,
            severity_weight=self.severity_weight,
            confidence=confidence,
            exposure=exposure,
            evidence=evidence or {},
            remediation=remediation,
            references=references or [],
        )
