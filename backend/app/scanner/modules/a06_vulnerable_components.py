"""OWASP A06 — Vulnerable and Outdated Components"""
import re, logging
from typing import List
import httpx
from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext
logger = logging.getLogger("vapt.scanner.a06")

KNOWN_VULNERABLE = [
    (re.compile(r"jQuery[/ v]([12]\.\d+\.\d+)", re.I), "jQuery < 3.0", "CVE-2020-11022", Severity.MEDIUM),
    (re.compile(r"jQuery[/ v](3\.[0-4]\.\d+)", re.I),  "jQuery 3.x < 3.5", "CVE-2020-11022", Severity.LOW),
    (re.compile(r"Bootstrap[/ v]([23]\.\d+\.\d+)", re.I), "Bootstrap < 4", "CVE-2019-8331", Severity.LOW),
    (re.compile(r"angular(?:js)?[/ v]1\.\d+\.\d+", re.I), "AngularJS 1.x (EOL)", "", Severity.MEDIUM),
    (re.compile(r"OpenSSL[/ ]1\.0\.", re.I), "OpenSSL 1.0.x (EOL)", "CVE-2022-0778", Severity.HIGH),
    (re.compile(r"Apache[/ ]2\.[0-2]\.", re.I), "Apache < 2.4 (EOL)", "", Severity.HIGH),
    (re.compile(r"PHP[/ ]([57]\.\d+\.\d+)", re.I), "PHP 5/7 (near-EOL)", "", Severity.MEDIUM),
    (re.compile(r"lodash[/ v](\d+\.\d+\.\d+)", re.I), "lodash (check for prototype pollution)", "CVE-2020-8203", Severity.MEDIUM),
]

class VulnerableComponentsModule(BaseModule):
    module_id = "a06_vulnerable_components"
    owasp_category = "A06"
    owasp_name = "Vulnerable and Outdated Components"
    severity_weight = 6.0

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        scan_text = ctx.response_body + " ".join(ctx.response_headers.values())
        for pattern, name, cve, severity in KNOWN_VULNERABLE:
            match = pattern.search(scan_text)
            if match:
                findings.append(self.build_finding(
                    title=f"Outdated/Vulnerable Component Detected: {name}",
                    description=(
                        f"Detected '{match.group(0)}' in the response at {ctx.url}. "
                        f"{name} has known security vulnerabilities{f' ({cve})' if cve else ''}. "
                        f"Attackers can use public exploits against this specific version."
                    ),
                    severity=severity, url=ctx.url,
                    evidence={
                        "detection_method": "component_version_pattern",
                        "matched_string": match.group(0),
                        "component": name,
                        "cve": cve,
                        "found_in": "response_body" if match.group(0) in ctx.response_body else "response_headers",
                    },
                    remediation=f"Update {name} to the latest patched version. Subscribe to security advisories.",
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve}"] if cve else [],
                    confidence=0.82,
                ))
        return findings
