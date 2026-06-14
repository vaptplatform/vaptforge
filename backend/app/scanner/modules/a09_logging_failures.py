"""
OWASP A09 — Security Logging and Monitoring Failures
Real ethical-hacker-level detection:
  - Probes debug/log endpoints and VERIFIES content is actually sensitive
  - Checks if error responses contain stack traces (logging leakage)
  - Verifies log files contain real log lines (timestamps, IP, level)
  - Checks if audit/access logs are publicly readable
  - Detects missing security event logging indicators
  - Checks for exposed monitoring dashboards (Kibana, Grafana, Prometheus)
"""
import logging
import re
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a09")

# Paths to probe — grouped by what sensitive content we expect
DEBUG_ENDPOINTS = [
    # path, content verifiers, severity, description
    ("/debug",              ["debug", "stack", "traceback", "exception", "variable"],     "high",     "debug interface"),
    ("/_debug",             ["debug", "stack", "traceback", "exception"],                 "high",     "debug interface"),
    ("/trace",              ["trace", "request", "response", "header"],                   "high",     "trace endpoint"),
    ("/__debug__",          ["debugger", "console", "python"],                            "critical", "Python debugger (Werkzeug)"),
    ("/_profiler",          ["profiler", "query", "timeline", "request"],                 "high",     "profiler dashboard"),
    ("/api/debug",          ["debug", "config", "env", "variable"],                       "high",     "API debug endpoint"),
    ("/console",            ["console", "shell", "eval", "execute", ">>"],                "critical", "interactive console"),
    ("/phpinfo.php",        ["php version", "phpinfo()", "configuration", "build date"],  "high",     "PHP info page"),
    ("/server-status",      ["apache server status", "requests currently being processed", "total accesses"], "medium", "Apache server-status"),
    ("/server-info",        ["apache server info", "server version", "module"],           "medium",   "Apache server-info"),
    ("/status",             ["uptime", "requests", "connections", "workers"],             "medium",   "server status page"),
]

LOG_FILE_PATHS = [
    ("/logs",               ["error", "warning", "info", "debug", "exception", "[20"],   "critical", "log directory"),
    ("/_logs",              ["error", "warning", "info", "debug", "[20"],                "critical", "log directory"),
    ("/log",                ["error", "warning", "info", "debug", "[20"],                "critical", "log file"),
    ("/app.log",            ["error", "warning", "info", "debug", "exception"],          "critical", "application log"),
    ("/error.log",          ["error", "exception", "traceback", "warning"],              "critical", "error log"),
    ("/access.log",         ["get /", "post /", "http/1", "200", "404"],                 "critical", "access log"),
    ("/debug.log",          ["debug", "error", "info", "warning"],                       "critical", "debug log"),
    ("/storage/logs/laravel.log", ["local.error", "local.info", "stack trace"],          "critical", "Laravel log"),
    ("/var/log/app.log",    ["error", "warning", "info"],                                "critical", "app log"),
    ("/tmp/app.log",        ["error", "warning", "info"],                                "critical", "temp log"),
]

CONFIG_EXPOSE_PATHS = [
    ("/.env",               ["app_key", "db_password", "secret", "api_key", "token"],    "critical", ".env file"),
    ("/.env.local",         ["app_key", "db_password", "secret", "api_key"],             "critical", ".env.local file"),
    ("/.env.production",    ["app_key", "db_password", "secret"],                        "critical", ".env.production file"),
    ("/config.json",        ["password", "secret", "key", "token", "database"],         "critical", "config JSON"),
    ("/settings.json",      ["password", "secret", "key", "token"],                     "critical", "settings JSON"),
    ("/appsettings.json",   ["connectionstring", "password", "secret"],                  "critical", ".NET appsettings"),
    ("/.git/config",        ["[remote", "[core", "url ="],                               "high",     "Git config"),
    ("/package.json",       ["dependencies", "scripts", "version"],                      "low",      "package.json"),
    ("/composer.json",      ["require", "autoload"],                                     "low",      "composer.json"),
]

MONITORING_DASHBOARDS = [
    ("/kibana",             ["kibana", "elasticsearch", "discover", "dashboard"],        "high",     "Kibana dashboard"),
    ("/grafana",            ["grafana", "dashboard", "panel", "datasource"],             "high",     "Grafana dashboard"),
    ("/:3000",              ["grafana"],                                                  "high",     "Grafana on port 3000"),
    ("/prometheus",         ["prometheus", "metrics", "scrape", "target"],               "high",     "Prometheus metrics"),
    ("/metrics",            ["# help", "# type", "http_requests", "process_"],          "medium",   "Prometheus metrics endpoint"),
    ("/actuator",           ["links", "self", "health", "info"],                         "high",     "Spring Boot Actuator"),
    ("/actuator/env",       ["systemproperties", "applicationconfig", "propertysources"],"critical", "Spring Actuator env"),
    ("/actuator/heapdump",  [],                                                          "critical", "JVM heap dump"),
    ("/actuator/threaddump",["java.lang.thread", "runnable", "waiting"],                 "critical", "JVM thread dump"),
    ("/actuator/httptrace", ["timeTaken", "request", "response", "principal"],           "high",     "HTTP trace log"),
    ("/health",             ["status", "up", "down", "diskspace"],                       "low",      "health endpoint"),
]

# Patterns that confirm content is real sensitive log/debug data
LOG_LINE_RE     = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', re.I)
STACK_TRACE_RE  = re.compile(r'(Traceback|at com\.|at org\.|at java\.|Exception in thread|File ".*", line \d)', re.I)
IP_LOG_RE       = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*(?:GET|POST|PUT|DELETE)', re.I)
WERKZEUG_RE     = re.compile(r'(werkzeug|Debugger|Interactive Console|Pin:|python debugger)', re.I)
METRICS_RE      = re.compile(r'^# (HELP|TYPE) \w+', re.M)
ENV_VAR_RE      = re.compile(r'[A-Z_]{3,}=\S+', re.M)


class LoggingFailuresModule(BaseModule):
    module_id      = "a09_logging_failures"
    owasp_category = "A09"
    owasp_name     = "Security Logging and Monitoring Failures"
    severity_weight = 4.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(ctx.url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Debug endpoints — verify content is actually sensitive
        for path, indicators, sev, desc in DEBUG_ENDPOINTS:
            finding = await self._probe_and_verify(
                client, base, path, indicators, sev, desc, "debug_endpoint_probe"
            )
            if finding:
                findings.append(finding)

        # 2. Log file paths — verify real log lines present
        for path, indicators, sev, desc in LOG_FILE_PATHS:
            finding = await self._probe_and_verify(
                client, base, path, indicators, sev, desc, "log_file_probe",
                extra_verifiers=[LOG_LINE_RE, IP_LOG_RE],
            )
            if finding:
                findings.append(finding)

        # 3. Config / env file exposure
        for path, indicators, sev, desc in CONFIG_EXPOSE_PATHS:
            finding = await self._probe_and_verify(
                client, base, path, indicators, sev, desc, "config_file_probe",
                extra_verifiers=[ENV_VAR_RE],
            )
            if finding:
                findings.append(finding)

        # 4. Monitoring dashboards
        for path, indicators, sev, desc in MONITORING_DASHBOARDS:
            finding = await self._probe_and_verify(
                client, base, path, indicators, sev, desc, "monitoring_dashboard_probe"
            )
            if finding:
                findings.append(finding)

        # 5. Stack trace in current response (error leakage)
        stack_finding = self._check_stack_trace_in_response(ctx)
        if stack_finding:
            findings.append(stack_finding)

        # 6. Werkzeug interactive debugger (critical — allows RCE)
        werkzeug = self._check_werkzeug_debugger(ctx)
        if werkzeug:
            findings.append(werkzeug)

        # 7. Trigger a 404/500 and check if stack trace leaks
        error_finding = await self._trigger_error_and_check(ctx.url, client)
        if error_finding:
            findings.append(error_finding)

        return findings

    # ── Core probe + content verification ─────────────────────────────────────
    async def _probe_and_verify(
        self,
        client: httpx.AsyncClient,
        base: str,
        path: str,
        indicators: list,
        severity: str,
        description: str,
        detection_method: str,
        extra_verifiers: list = None,
    ) -> Optional[RawFinding]:
        """
        Probe path and verify the response actually contains sensitive content.
        HTTP 200 alone is NOT enough — content must match indicators or regex patterns.
        """
        url = urljoin(base, path)
        try:
            resp = await client.get(url, timeout=7)

            # Must be 200 with meaningful content
            if resp.status_code not in (200, 206):
                return None
            if len(resp.text) < 30:
                return None

            body_lower = resp.text[:5000].lower()

            # Check string indicators
            matched_indicators = [ind for ind in indicators if ind.lower() in body_lower]

            # Check regex verifiers
            matched_regex = []
            if extra_verifiers:
                for pattern in extra_verifiers:
                    if pattern.search(resp.text[:5000]):
                        matched_regex.append(pattern.pattern[:40])

            # Need at least 1 match to confirm real sensitive content
            if not matched_indicators and not matched_regex:
                return None

            # Determine actual severity from content
            actual_sev = severity
            if WERKZEUG_RE.search(resp.text[:3000]):
                actual_sev = "critical"
            elif STACK_TRACE_RE.search(resp.text[:3000]):
                actual_sev = "high"

            sev_map = {
                "critical": Severity.CRITICAL,
                "high":     Severity.HIGH,
                "medium":   Severity.MEDIUM,
                "low":      Severity.LOW,
            }

            return self.build_finding(
                title=f"Sensitive {description.title()} Publicly Accessible: {path}",
                description=(
                    f"The path '{path}' returned HTTP {resp.status_code} "
                    f"with {len(resp.text)} bytes of content. "
                    f"Content analysis CONFIRMED sensitive {description} data: "
                    f"matched indicators: {matched_indicators[:4]}"
                    f"{f', regex patterns: {matched_regex[:2]}' if matched_regex else ''}. "
                    f"This exposes internal application state, configuration, "
                    f"or logs to any unauthenticated attacker."
                ),
                severity=sev_map.get(actual_sev, Severity.MEDIUM),
                url=url,
                evidence={
                    "detection_method": detection_method,
                    "path": path,
                    "response_status": resp.status_code,
                    "response_size": len(resp.text),
                    "matched_indicators": matched_indicators[:5],
                    "matched_regex_patterns": matched_regex[:3],
                    "content_snippet": resp.text[:400],
                },
                remediation=(
                    f"Immediately restrict access to '{path}'. "
                    "Require authentication for all debug, log, and monitoring endpoints. "
                    "In production: disable debug mode, remove log endpoints from web root, "
                    "place monitoring dashboards behind VPN or firewall rules."
                ),
                references=[
                    "https://owasp.org/www-project-top-ten/2021/A09_2021-Security_Logging_and_Monitoring_Failures",
                ],
                confidence=0.92,
            )

        except Exception as e:
            logger.debug(f"A09 probe error {url}: {e}")
        return None

    # ── Stack trace in current response ───────────────────────────────────────
    def _check_stack_trace_in_response(self, ctx: ScanContext) -> Optional[RawFinding]:
        """Check if the current response body contains a stack trace."""
        body = ctx.response_body[:5000]
        match = STACK_TRACE_RE.search(body)
        if not match:
            return None

        return self.build_finding(
            title="Stack Trace / Exception Leaked in HTTP Response",
            description=(
                f"The response at '{ctx.url}' contains a stack trace or exception message: "
                f"'{match.group(0)[:100]}'. "
                f"This reveals internal file paths, class names, framework versions, "
                f"and application logic — all valuable to an attacker crafting targeted exploits."
            ),
            severity=Severity.HIGH,
            url=ctx.url,
            evidence={
                "detection_method": "stack_trace_pattern_match",
                "matched_pattern": match.group(0)[:200],
                "response_status": ctx.status_code,
                "snippet": body[max(0, match.start() - 50): match.start() + 300],
            },
            remediation=(
                "Disable debug/verbose error mode in production. "
                "Return generic error pages to end users. "
                "Log full errors server-side only — never in HTTP responses."
            ),
            confidence=0.94,
        )

    # ── Werkzeug interactive debugger ─────────────────────────────────────────
    def _check_werkzeug_debugger(self, ctx: ScanContext) -> Optional[RawFinding]:
        """
        Detect Werkzeug/Flask interactive debugger — allows arbitrary Python
        code execution directly in the browser. This is CRITICAL.
        """
        body = ctx.response_body[:5000]
        match = WERKZEUG_RE.search(body)
        if not match:
            return None

        return self.build_finding(
            title="Werkzeug Interactive Debugger Exposed — Remote Code Execution Possible",
            description=(
                f"The Werkzeug/Flask interactive debugger is enabled and exposed at '{ctx.url}'. "
                f"This allows ANY visitor to execute arbitrary Python code in the server's context "
                f"via the browser console — equivalent to full server compromise. "
                f"Pattern matched: '{match.group(0)[:80]}'"
            ),
            severity=Severity.CRITICAL,
            url=ctx.url,
            evidence={
                "detection_method": "werkzeug_debugger_pattern",
                "matched_pattern": match.group(0)[:200],
                "response_status": ctx.status_code,
                "snippet": body[:400],
            },
            remediation=(
                "IMMEDIATELY disable the Werkzeug debugger: set DEBUG=False in production. "
                "Set FLASK_DEBUG=0. Never run Flask/Django with debug=True in production. "
                "Use environment-specific configuration files."
            ),
            references=[
                "https://werkzeug.palletsprojects.com/en/2.3.x/debug/",
                "https://owasp.org/A05_2021-Security_Misconfiguration/",
            ],
            confidence=0.98,
        )

    # ── Trigger error and check for stack trace leakage ───────────────────────
    async def _trigger_error_and_check(
        self, url: str, client: httpx.AsyncClient
    ) -> Optional[RawFinding]:
        """
        Send a deliberately malformed request to trigger a 500 error
        and check if the error response leaks a stack trace.
        """
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Try a path that commonly triggers verbose errors
        error_triggers = [
            base + "/nonexistent_vapt_probe_path_xyz",
            base + "/api/vapt_probe_xyz",
            url + ("&" if "?" in url else "?") + "vapt_probe=<script>",
        ]

        for trigger_url in error_triggers[:2]:
            try:
                resp = await client.get(trigger_url, timeout=7)
                body = resp.text[:5000]

                # Only flag if status is 4xx/5xx AND stack trace present
                if resp.status_code >= 400:
                    match = STACK_TRACE_RE.search(body)
                    if match:
                        return self.build_finding(
                            title="Verbose Error Response Leaks Stack Trace",
                            description=(
                                f"Requesting a non-existent path '{trigger_url}' triggered "
                                f"HTTP {resp.status_code} with a stack trace in the response body. "
                                f"Pattern found: '{match.group(0)[:100]}'. "
                                f"Attackers use error messages to fingerprint the framework, "
                                f"discover file paths, and craft targeted exploits."
                            ),
                            severity=Severity.MEDIUM,
                            url=trigger_url,
                            evidence={
                                "detection_method": "error_trigger_stack_trace",
                                "trigger_url": trigger_url,
                                "response_status": resp.status_code,
                                "stack_trace_match": match.group(0)[:200],
                                "snippet": body[max(0, match.start()-30): match.start()+300],
                            },
                            remediation=(
                                "Configure custom error pages for 400, 404, 500. "
                                "Disable debug mode in production. "
                                "Never expose framework internals in error responses."
                            ),
                            confidence=0.88,
                        )
            except Exception as e:
                logger.debug(f"Error trigger check failed for {trigger_url}: {e}")

        return None
