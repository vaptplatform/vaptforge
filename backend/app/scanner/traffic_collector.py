"""
Traffic Collection & Analysis Engine
Captures, stores, and analyzes HTTP request/response traffic during scans.
Provides behavioral profiling, anomaly detection, and response diffing.
"""
import hashlib
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx

logger = logging.getLogger("vapt.traffic")


@dataclass
class TrafficRecord:
    """Represents a single captured HTTP request/response pair."""
    record_id: str
    scan_id: str
    timestamp: str
    # Request
    method: str
    url: str
    request_headers: Dict[str, str]
    request_params: Dict[str, str]
    request_body: Optional[str]
    # Response
    status_code: int
    response_headers: Dict[str, str]
    response_body_size: int
    response_time_ms: int
    content_type: str
    # Analysis
    anomaly_flags: List[str] = field(default_factory=list)
    is_error_response: bool = False
    has_sensitive_data: bool = False
    redirects: int = 0


@dataclass
class EndpointProfile:
    """Behavioral profile for a single endpoint accumulated over multiple requests."""
    url: str
    method: str
    request_count: int = 0
    avg_response_time_ms: float = 0.0
    status_code_distribution: Dict[int, int] = field(default_factory=dict)
    avg_body_size: float = 0.0
    param_names: List[str] = field(default_factory=list)
    content_types: List[str] = field(default_factory=list)
    error_count: int = 0
    anomalies: List[str] = field(default_factory=list)


class TrafficCollector:
    """
    Collects and stores request/response traffic for a scan session.
    Maintains in-memory store during scan; findings written to DB at completion.
    """

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self._records: List[TrafficRecord] = []
        self._endpoint_profiles: Dict[str, EndpointProfile] = {}
        self._baseline_responses: Dict[str, str] = {}  # url_hash -> body for diffing

    def record(
        self,
        method: str,
        url: str,
        request_headers: Dict,
        params: Dict,
        response: httpx.Response,
        response_time_ms: int,
        request_body: str = None,
    ) -> TrafficRecord:
        """Record a request/response pair and update endpoint profile."""
        record_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:12]
        body_text = ""
        try:
            body_text = response.text
        except Exception:
            pass

        content_type = response.headers.get("content-type", "")
        is_error = response.status_code >= 400

        record = TrafficRecord(
            record_id=record_id,
            scan_id=self.scan_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            method=method,
            url=url,
            request_headers={k: v for k, v in request_headers.items() if k.lower() not in ("authorization", "cookie")},
            request_params=params,
            request_body=request_body,
            status_code=response.status_code,
            response_headers=dict(response.headers),
            response_body_size=len(body_text),
            response_time_ms=response_time_ms,
            content_type=content_type,
            is_error_response=is_error,
            redirects=len(response.history),
        )

        # Anomaly flags
        record.anomaly_flags = self._detect_anomalies(record, body_text)
        self._records.append(record)
        self._update_profile(record)

        return record

    def set_baseline(self, url: str, body: str) -> None:
        """Store baseline response for a URL (used in diffing)."""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        self._baseline_responses[url_hash] = body

    def diff_against_baseline(self, url: str, new_body: str) -> float:
        """Returns 0.0 (same) – 1.0 (completely different) vs baseline."""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        baseline = self._baseline_responses.get(url_hash, "")
        if not baseline and not new_body:
            return 0.0
        if not baseline or not new_body:
            return 1.0
        diff = abs(len(baseline) - len(new_body)) / max(len(baseline), len(new_body))
        # Also check content similarity by shared tokens
        b_words = set(baseline.split())
        n_words = set(new_body.split())
        if b_words:
            token_diff = 1.0 - len(b_words & n_words) / max(len(b_words), 1)
            diff = max(diff, token_diff * 0.5)
        return round(min(diff, 1.0), 3)

    def _detect_anomalies(self, record: TrafficRecord, body: str) -> List[str]:
        flags = []
        if record.response_time_ms > 8000:
            flags.append(f"slow_response:{record.response_time_ms}ms")
        if record.status_code in (500, 502, 503):
            flags.append(f"server_error:{record.status_code}")
        if record.response_body_size > 5_000_000:
            flags.append("large_response")
        if record.redirects > 5:
            flags.append(f"excessive_redirects:{record.redirects}")
        # Check for error keywords in body
        error_keywords = ["exception", "stack trace", "traceback", "syntax error", "undefined method"]
        if any(kw in body.lower() for kw in error_keywords):
            flags.append("error_disclosure")
        return flags

    def _update_profile(self, record: TrafficRecord) -> None:
        from urllib.parse import urlparse
        parsed = urlparse(record.url)
        key = f"{record.method}:{parsed.scheme}://{parsed.netloc}{parsed.path}"

        if key not in self._endpoint_profiles:
            self._endpoint_profiles[key] = EndpointProfile(url=key, method=record.method)

        profile = self._endpoint_profiles[key]
        # Running average
        n = profile.request_count
        profile.avg_response_time_ms = (profile.avg_response_time_ms * n + record.response_time_ms) / (n + 1)
        profile.avg_body_size = (profile.avg_body_size * n + record.response_body_size) / (n + 1)
        profile.request_count += 1
        profile.status_code_distribution[record.status_code] = (
            profile.status_code_distribution.get(record.status_code, 0) + 1
        )
        if record.is_error_response:
            profile.error_count += 1
        if record.content_type not in profile.content_types:
            profile.content_types.append(record.content_type)
        for param in record.request_params:
            if param not in profile.param_names:
                profile.param_names.append(param)
        profile.anomalies.extend(record.anomaly_flags)

    # ── Public accessors ──────────────────────────────────────────────────────

    def get_all_records(self) -> List[TrafficRecord]:
        return self._records

    def get_endpoint_profiles(self) -> Dict[str, EndpointProfile]:
        return self._endpoint_profiles

    def get_summary(self) -> dict:
        total = len(self._records)
        errors = sum(1 for r in self._records if r.is_error_response)
        slow = sum(1 for r in self._records if r.response_time_ms > 3000)
        anomalous = sum(1 for r in self._records if r.anomaly_flags)
        return {
            "total_requests": total,
            "error_responses": errors,
            "slow_responses": slow,
            "anomalous_responses": anomalous,
            "unique_endpoints": len(self._endpoint_profiles),
            "status_codes": self._status_code_summary(),
        }

    def _status_code_summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for r in self._records:
            bucket = f"{r.status_code // 100}xx"
            counts[bucket] += 1
        return dict(counts)

    def get_high_risk_endpoints(self) -> List[dict]:
        """Return endpoints with highest anomaly/error rates."""
        results = []
        for key, profile in self._endpoint_profiles.items():
            if profile.request_count == 0:
                continue
            error_rate = profile.error_count / profile.request_count
            anomaly_count = len(set(profile.anomalies))
            score = error_rate * 5 + anomaly_count * 2 + (1 if profile.avg_response_time_ms > 3000 else 0)
            if score > 1:
                results.append({
                    "endpoint": key,
                    "risk_score": round(score, 2),
                    "error_rate": round(error_rate, 2),
                    "avg_response_time_ms": round(profile.avg_response_time_ms),
                    "anomalies": list(set(profile.anomalies))[:5],
                    "request_count": profile.request_count,
                })
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)
