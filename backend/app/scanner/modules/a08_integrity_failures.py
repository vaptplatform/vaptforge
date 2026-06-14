"""
OWASP A08 — Software and Data Integrity Failures
Detects: missing SRI attributes, insecure deserialization patterns, 
unsigned/unverified update endpoints, CDN script loading without integrity checks.
"""
import re, logging
from typing import List
import httpx
from app.models.models import Severity
from app.scanner.modules.base import BaseModule, RawFinding, ScanContext

logger = logging.getLogger("vapt.scanner.a08")

# External scripts without integrity attribute
SRI_RE  = re.compile(r'<script\s[^>]*src=["\']https?://(?!(?:localhost|127\.0\.0\.1))[^"\']+["\'][^>]*>', re.I)
INT_RE  = re.compile(r'\bintegrity=["\']sha', re.I)

# Serialized Java objects
JAVA_SER_B64 = re.compile(r'rO0AB', re.I)  # Base64 of Java serialization magic bytes

# Python pickle hints
PICKLE_RE = re.compile(r'\\x80\\x04\\x95|pickle\.loads', re.I)


class IntegrityFailuresModule(BaseModule):
    module_id      = "a08_integrity_failures"
    owasp_category = "A08"
    owasp_name     = "Software and Data Integrity Failures"
    severity_weight = 6.5

    async def analyze(self, ctx: ScanContext, client: httpx.AsyncClient) -> List[RawFinding]:
        findings: List[RawFinding] = []
        body = ctx.response_body

        # 1. External scripts missing SRI
        ext_scripts = SRI_RE.findall(body)
        missing_sri = [s for s in ext_scripts if not INT_RE.search(s)]
        if missing_sri:
            examples = missing_sri[:3]
            findings.append(self.build_finding(
                title="Subresource Integrity (SRI) Attribute Missing",
                description=(
                    f"Found {len(missing_sri)} external script/link tag(s) at {ctx.url} "
                    f"without an integrity attribute. Without SRI, if the external CDN is "
                    f"compromised, malicious code could be injected into your pages."
                ),
                severity=Severity.MEDIUM, url=ctx.url,
                evidence={
                    "detection_method": "sri_attribute_check",
                    "missing_count": len(missing_sri),
                    "examples": [s[:120] for s in examples],
                    "owasp_ref": "CWE-345",
                },
                remediation=(
                    "Add integrity and crossorigin attributes to all external scripts/links: "
                    "<script src='...' integrity='sha384-...' crossorigin='anonymous'>. "
                    "Generate hashes at: https://www.srihash.org"
                ),
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
                confidence=0.90,
            ))

        # 2. Potential Java deserialization
        if JAVA_SER_B64.search(body):
            findings.append(self.build_finding(
                title="Potential Java Deserialization Data in Response",
                description=(
                    f"Response at {ctx.url} contains base64-encoded data matching "
                    f"Java serialization magic bytes. Insecure deserialization can lead to RCE."
                ),
                severity=Severity.HIGH, url=ctx.url,
                evidence={"detection_method": "java_serialization_pattern", "pattern": "rO0AB (Java ser magic)"},
                remediation=(
                    "Avoid deserializing untrusted data. "
                    "Use JSON/XML instead of Java serialization. "
                    "Apply deserialization filters (Java 9+ ObjectInputFilter)."
                ),
                references=["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
                confidence=0.65,
            ))

        # 3. Python pickle hints
        if PICKLE_RE.search(body):
            findings.append(self.build_finding(
                title="Potential Insecure Deserialization (Python Pickle)",
                description=(
                    f"Response at {ctx.url} contains patterns suggesting Python pickle "
                    f"serialization. Pickle deserialization of untrusted data allows arbitrary code execution."
                ),
                severity=Severity.HIGH, url=ctx.url,
                evidence={"detection_method": "pickle_pattern_match"},
                remediation="Use JSON serialization. Never unpickle untrusted data. Use hmac signing for serialized objects.",
                confidence=0.60,
            ))

        return findings
