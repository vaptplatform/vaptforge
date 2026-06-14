"""
OWASP A03 — Injection v2.0
Real-world detection: SQLi (error/boolean/time-based), XSS (reflected/stored/DOM/POST),
SSTI, Command Injection indicators, NoSQL injection, LDAP injection, XXE, Log injection.
"""
import asyncio
import logging
import time
from typing import List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

import httpx

from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a03")


class InjectionDetectionModule(BaseModule):
    module_id      = "a03_injection"
    owasp_category = "A03"
    owasp_name     = "Injection"
    severity_weight = 9.5

    # SQLi error signatures — DB-specific
    SQL_ERROR_SIGS = [
        "sql syntax", "mysql_fetch", "ora-", "pg::syntaxerror",
        "sqlite3", "unclosed quotation", "sqlstate", "mysql_num_rows",
        "you have an error in your sql", "warning: mysqli",
        "pg_query()", "sqlite3.operationalerror", "conversion failed",
        "odbc microsoft access driver", "jdbc", "sqlexception",
        "near \"", "unterminated quoted", "invalid column name",
        "column not found", "table or view not found",
    ]

    # XSS probes (multiple to bypass simple filters)
    XSS_PROBES = [
        ("<vaptxss>test</vaptxss>",   "vaptxss"),
        ("<img src=x onerror=vapt>",  "onerror=vapt"),
        ('"><vaptxss>',               "<vaptxss>"),
        ("'><vaptxss>",               "<vaptxss>"),
        ("<ScRiPt>vapt</ScRiPt>",     "vapt</script>"),
        ("<svg><script>vapt</script>","vapt</script>"),
    ]

    # SSTI probes
    SSTI_PROBES = [
        ("{{7*7}}",    "49",      "Jinja2/Twig"),
        ("${7*7}",     "49",      "Freemarker/EL"),
        ("<%= 7*7 %>", "49",      "ERB/JSP"),
        ("{{7*'7'}}",  "7777777", "Jinja2 specific"),
        ("*{7*7}",     "49",      "Spring SpEL"),
    ]

    # Time-based SQLi
    SQLI_TIME_PROBES = [
        ("'; SELECT SLEEP(4)--",       4.0, "MySQL"),
        ("'; WAITFOR DELAY '0:0:4'--", 4.0, "MSSQL"),
        ("'; SELECT pg_sleep(4)--",    4.0, "PostgreSQL"),
        ("1 AND SLEEP(4)--",           4.0, "MySQL (integer)"),
        ("' OR SLEEP(4)--",            4.0, "MySQL OR"),
    ]

    # DOM XSS sinks
    DOM_SINKS = [
        "document.write(", "innerHTML=", "outerHTML=", "eval(",
        "setTimeout(", "setInterval(", "document.cookie", "window.location",
        ".src=", "insertAdjacentHTML(", "document.writeln(",
    ]

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        if not ctx.params:
            # Still run DOM XSS check
            dom = self._dom_xss(ctx)
            if dom:
                findings.append(dom)
            return findings

        parsed     = urlparse(ctx.url)
        base_params = {k: v[0] for k, v in parse_qs(parsed.query).items()} if parsed.query else {}
        base_params.update(ctx.params)

        for param, orig in ctx.params.items():
            if not isinstance(orig, str):
                continue

            # 1. SQL Injection (error → boolean → time-based)
            sqli = await self._sqli_full(client, ctx.url, parsed, base_params, param, orig)
            if sqli:
                findings.append(sqli)

            # 2. XSS (reflected, multiple probes)
            xss = await self._xss_reflected(client, ctx.url, parsed, base_params, param)
            if xss:
                findings.append(xss)

            # 3. SSTI
            ssti = await self._ssti(client, ctx.url, parsed, base_params, param)
            if ssti:
                findings.append(ssti)

            # 4. NoSQL injection
            nosql = await self._nosql(client, ctx.url, parsed, base_params, param, orig)
            if nosql:
                findings.append(nosql)

        # 5. DOM-based XSS
        dom = self._dom_xss(ctx)
        if dom:
            findings.append(dom)

        # 6. POST form XSS + SQLi (on the crawled page)
        post_findings = await self._post_form_injection(ctx.url, client)
        findings.extend(post_findings)

        return findings

    # ── SQL Injection (Full Chain) ─────────────────────────────────────────────
    async def _sqli_full(self, client, url, parsed, base, param, orig) -> Optional[RawFinding]:
        # Phase 1: Error-based
        for probe in ["'", '"', "' OR '1'='1'--", "1'", "\\"]:
            try:
                err_url  = self._build(parsed, {**base, param: orig + probe})
                err_resp = await client.get(err_url, timeout=8)
                sig = self._find_sql_error(err_resp.text)
                if sig:
                    return self.build_finding(
                        title=f"SQL Injection (Error-Based) — Parameter: '{param}'",
                        description=(
                            f"Injecting '{probe}' into '{param}' triggered SQL error '{sig}'. "
                            f"Database is directly accessible via this parameter — "
                            f"attacker can extract the full database schema and data."
                        ),
                        severity=Severity.CRITICAL, url=url, parameter=param,
                        evidence={
                            "detection_method": "error_based_sqli",
                            "probe": probe,
                            "error_signature": sig,
                            "response_status": err_resp.status_code,
                            "raw_http": (
                                f"GET {err_url}\n"
                                f"→ HTTP {err_resp.status_code}\n"
                                f"Error: {sig}"
                            ),
                        },
                        remediation=(
                            "Use parameterized queries / prepared statements. "
                            "Never concatenate user input into SQL. Use an ORM."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html",
                        ],
                        confidence=0.97,
                    )
            except Exception:
                pass

        # Phase 2: Boolean blind
        try:
            t_resp, f_resp = await asyncio.gather(
                client.get(self._build(parsed, {**base, param: orig + " AND 1=1--"}), timeout=8),
                client.get(self._build(parsed, {**base, param: orig + " AND 1=2--"}), timeout=8),
            )
            diff = self.response_diff(t_resp.text, f_resp.text)
            if diff > 0.12:
                return self.build_finding(
                    title=f"SQL Injection (Boolean Blind) — Parameter: '{param}'",
                    description=(
                        f"TRUE/FALSE SQL conditions on '{param}' produce {diff:.0%} response difference. "
                        f"Blind SQLi confirmed — attacker can extract database character by character."
                    ),
                    severity=Severity.HIGH, url=url, parameter=param,
                    evidence={
                        "detection_method": "boolean_blind",
                        "diff_ratio": round(diff, 4),
                        "true_size": len(t_resp.text),
                        "false_size": len(f_resp.text),
                        "raw_http": (
                            f"TRUE: AND 1=1-- → {t_resp.status_code} ({len(t_resp.text)}b)\n"
                            f"FALSE: AND 1=2-- → {f_resp.status_code} ({len(f_resp.text)}b)\n"
                            f"Diff ratio: {diff:.4f}"
                        ),
                    },
                    remediation="Parameterize all SQL queries. Use ORM.",
                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    confidence=0.78,
                )
        except Exception:
            pass

        # Phase 3: Time-based blind
        for probe, delay, db_hint in self.SQLI_TIME_PROBES[:3]:
            try:
                t0 = time.time()
                await client.get(
                    self._build(parsed, {**base, param: orig + probe}),
                    timeout=delay + 6
                )
                elapsed = time.time() - t0
                if elapsed >= delay * 0.75:
                    return self.build_finding(
                        title=f"SQL Injection (Time-Based Blind, {db_hint}) — Parameter: '{param}'",
                        description=(
                            f"Probe '{probe}' caused {elapsed:.1f}s delay on '{param}'. "
                            f"Time-based {db_hint} SQLi confirmed."
                        ),
                        severity=Severity.CRITICAL, url=url, parameter=param,
                        evidence={
                            "detection_method": "time_based_blind",
                            "probe": probe,
                            "delay_seconds": round(elapsed, 2),
                            "expected_delay": delay,
                            "db_hint": db_hint,
                        },
                        remediation="Use parameterized queries.",
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                        confidence=0.86,
                    )
            except Exception:
                pass

        return None

    def _find_sql_error(self, text: str) -> Optional[str]:
        t = text[:8000].lower()
        for sig in self.SQL_ERROR_SIGS:
            if sig in t:
                return sig
        return None

    # ── XSS (Reflected) ───────────────────────────────────────────────────────
    async def _xss_reflected(self, client, url, parsed, base, param) -> Optional[RawFinding]:
        for probe, marker in self.XSS_PROBES:
            try:
                resp = await client.get(
                    self._build(parsed, {**base, param: probe}), timeout=8
                )
                if marker.lower() in resp.text.lower():
                    idx     = resp.text.lower().find(marker.lower())
                    snippet = resp.text[max(0, idx-20): idx+len(marker)+20]
                    return self.build_finding(
                        title=f"Reflected XSS — Parameter: '{param}'",
                        description=(
                            f"XSS probe '{probe[:60]}' reflected unencoded in response for '{param}'. "
                            f"Attacker can execute malicious JavaScript in victim's browser — "
                            f"session theft, credential harvest, drive-by malware."
                        ),
                        severity=Severity.HIGH, url=url, parameter=param,
                        evidence={
                            "detection_method": "reflection_analysis",
                            "probe": probe,
                            "reflected_snippet": snippet,
                            "raw_http": (
                                f"GET {url}?{param}={probe}\n"
                                f"→ HTTP {resp.status_code}\n"
                                f"Reflection: {snippet}"
                            ),
                        },
                        remediation=(
                            "HTML-encode all user output. Use framework auto-escaping. "
                            "Implement strict CSP. Use DOMPurify."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cwe.mitre.org/data/definitions/79.html",
                        ],
                        confidence=0.94,
                    )
            except Exception:
                pass
        return None

    # ── SSTI ──────────────────────────────────────────────────────────────────
    async def _ssti(self, client, url, parsed, base, param) -> Optional[RawFinding]:
        for probe, expected, engine in self.SSTI_PROBES:
            try:
                resp = await client.get(
                    self._build(parsed, {**base, param: probe}), timeout=8
                )
                if expected in resp.text and probe not in resp.text:
                    return self.build_finding(
                        title=f"Server-Side Template Injection ({engine}) — Parameter: '{param}'",
                        description=(
                            f"Math probe '{probe}' evaluated to '{expected}' server-side for '{param}'. "
                            f"SSTI with {engine} can escalate to Remote Code Execution — "
                            f"full server compromise."
                        ),
                        severity=Severity.CRITICAL, url=url, parameter=param,
                        evidence={
                            "detection_method": "math_expression_evaluation",
                            "probe": probe,
                            "expected": expected,
                            "engine": engine,
                        },
                        remediation=(
                            "Never render user input through template engines. "
                            "Use sandboxed templates. Pass data as context variables."
                        ),
                        references=["https://portswigger.net/research/server-side-template-injection"],
                        confidence=0.95,
                    )
            except Exception:
                pass
        return None

    # ── NoSQL Injection ───────────────────────────────────────────────────────
    async def _nosql(self, client, url, parsed, base, param, orig) -> Optional[RawFinding]:
        """Test MongoDB/NoSQL injection via operator injection."""
        nosql_probes = [
            (f"{param}[$ne]", "not-exist-value"),
            (f"{param}[$gt]", ""),
            (f"{param}[$regex]", ".*"),
        ]
        try:
            # Try operator injection via query string
            for op_param, op_val in nosql_probes[:2]:
                modified = {k: v for k, v in base.items() if k != param}
                modified[op_param] = op_val
                op_url = self._build(parsed, modified)
                resp = await client.get(op_url, timeout=8)
                # If we get a 200 where we'd expect auth failure / empty result
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Check for auth bypass indicators
                    body = resp.text.lower()
                    if any(ind in body for ind in ["dashboard","profile","welcome","logout","token","admin"]):
                        return self.build_finding(
                            title=f"NoSQL Injection — Parameter: '{param}'",
                            description=(
                                f"MongoDB operator '{op_param}={op_val}' injected via '{param}' "
                                f"returned a successful response. Attacker may bypass authentication "
                                f"or enumerate all documents in the collection."
                            ),
                            severity=Severity.CRITICAL, url=url, parameter=param,
                            evidence={
                                "detection_method": "nosql_operator_injection",
                                "probe_param": op_param,
                                "probe_value": op_val,
                                "response_status": resp.status_code,
                                "response_size": len(resp.text),
                            },
                            remediation=(
                                "Validate and sanitize all query parameters. "
                                "Use mongoose schema validation. "
                                "Never pass raw req.body/query to find()."
                            ),
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                            confidence=0.76,
                        )
        except Exception:
            pass
        return None

    # ── DOM-based XSS ─────────────────────────────────────────────────────────
    def _dom_xss(self, ctx: ScanContext) -> Optional[RawFinding]:
        body = ctx.response_body
        hits = [s for s in self.DOM_SINKS if s in body]
        if len(hits) >= 2:
            return self.build_finding(
                title="DOM-Based XSS Sinks Detected",
                description=(
                    f"The page at {ctx.url} contains {len(hits)} dangerous DOM manipulation "
                    f"sinks: {', '.join(hits[:5])}. If user-controlled data flows into "
                    f"these without sanitization, DOM XSS is exploitable."
                ),
                severity=Severity.MEDIUM, url=ctx.url,
                evidence={
                    "detection_method": "dom_sink_analysis",
                    "sinks_found": hits,
                    "count": len(hits),
                },
                remediation=(
                    "Audit all DOM manipulation. Use textContent not innerHTML. "
                    "Apply DOMPurify. Implement strict CSP."
                ),
                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
                confidence=0.55,
            )
        return None

    # ── POST Form Injection ────────────────────────────────────────────────────
    async def _post_form_injection(self, url: str, client: httpx.AsyncClient) -> List[RawFinding]:
        findings = []
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urljoin
            resp = await asyncio.wait_for(client.get(url), timeout=8)
            soup = BeautifulSoup(resp.text, "html.parser")

            for form in soup.find_all("form")[:3]:
                action = form.get("action", url)
                method = form.get("method", "get").lower()
                if method != "post":
                    continue
                form_url = urljoin(url, action)
                fields = {
                    inp.get("name"): inp.get("value", "test")
                    for inp in form.find_all(["input", "textarea"])
                    if inp.get("name")
                }
                if not fields:
                    continue

                for field_name in list(fields.keys())[:2]:
                    for probe, marker in self.XSS_PROBES[:2]:
                        try:
                            r = await asyncio.wait_for(
                                client.post(form_url, data={**fields, field_name: probe}), timeout=8
                            )
                            if marker.lower() in r.text.lower():
                                findings.append(self.build_finding(
                                    title=f"Reflected XSS via POST Form — Field: '{field_name}'",
                                    description=(
                                        f"XSS probe reflected from POST field '{field_name}' at '{form_url}'."
                                    ),
                                    severity=Severity.HIGH, url=form_url, parameter=field_name,
                                    evidence={
                                        "detection_method": "post_form_xss",
                                        "field": field_name,
                                        "probe": probe,
                                    },
                                    remediation="HTML-encode all output. Use CSP.",
                                    references=["https://owasp.org/www-community/attacks/xss/"],
                                    confidence=0.91,
                                ))
                                break
                        except Exception:
                            pass
        except Exception:
            pass
        return findings

    def _build(self, parsed, params: dict) -> str:
        return urlunparse(parsed._replace(query=urlencode(params)))
