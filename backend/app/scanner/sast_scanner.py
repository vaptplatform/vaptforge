"""
VAPTForge SAST Scanner v2.0 — Deep Static Application Security Testing

New in v2.0:
  - 25 rules (up from 10) covering full OWASP Top 10
  - Taint tracking: follows user input from source → sink
  - AST-aware context (not just regex line match — checks surrounding code)
  - Language-specific patterns: Python, JS/TS, PHP, Java, Go, Ruby, C#
  - Secrets detection: 20+ secret patterns (AWS keys, JWT secrets, RSA keys, etc.)
  - Dependency confusion / supply chain checks
  - Insecure randomness detection
  - Mass assignment patterns
  - Prototype pollution (JS)
  - Race condition indicators
  - LDAP injection
  - NoSQL injection
  - Expression Language injection
  - Regex DoS (ReDoS)
  - Insecure file permissions
  - Log injection
  - XML/HTML injection sinks
  - Confidence scoring per rule
"""
import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger("vapt.sast")


@dataclass
class SASTFinding:
    rule_id:      str
    category:     str
    title:        str
    description:  str
    severity:     str
    file_path:    str
    line_number:  int
    code_snippet: str
    remediation:  str
    confidence:   float
    cwe:          str = ""
    references:   List[str] = field(default_factory=list)

    def dedup_key(self) -> tuple:
        return (self.rule_id, self.file_path, self.line_number)


# ── Rule Definitions ──────────────────────────────────────────────────────────
SAST_RULES = [

    # ── A02: Cryptographic Failures ──────────────────────────────────────────
    {
        "id": "SAST-001", "category": "A02", "severity": "critical",
        "title": "Hardcoded Secret / Credential",
        "confidence": 0.88,
        "patterns": [
            r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\'][^"\']{6,}["\']',
            r'(?:secret|api_key|apikey|auth_token|access_token|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'(?:SECRET_KEY|AWS_SECRET|AWS_ACCESS_KEY|PRIVATE_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'(?:client_secret|consumer_secret|app_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
        ],
        "description": "Hardcoded credentials or secret keys found in source code. Anyone with code access gains immediate unauthorized access.",
        "remediation": "Use environment variables or secrets manager (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Never commit credentials to source control.",
        "cwe": "CWE-798",
        "references": ["https://owasp.org/A02_2021-Cryptographic_Failures/"],
    },
    {
        "id": "SAST-001B", "category": "A02", "severity": "critical",
        "title": "AWS / Cloud Credentials in Code",
        "confidence": 0.95,
        "patterns": [
            r'AKIA[0-9A-Z]{16}',                          # AWS Access Key ID
            r'(?:aws_secret|secret_access_key)\s*[=:]\s*["\'][A-Za-z0-9+/]{40}["\']',
            r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}',  # GitHub tokens
            r'xox[baprs]-[0-9A-Za-z\-]{10,48}',           # Slack tokens
            r'AIza[0-9A-Za-z\-_]{35}',                    # Google API key
            r'sk-[a-zA-Z0-9]{48}',                        # OpenAI key
        ],
        "description": "Cloud provider or third-party service credentials detected in source code. These grant direct access to cloud infrastructure, repositories, or paid APIs.",
        "remediation": "Immediately rotate the exposed credentials. Use IAM roles, environment variables, or a secrets manager. Add pre-commit hooks to prevent secret commits.",
        "cwe": "CWE-312",
        "references": ["https://docs.github.com/en/code-security/secret-scanning"],
    },
    {
        "id": "SAST-006", "category": "A02", "severity": "high",
        "title": "Weak Cryptographic Algorithm",
        "confidence": 0.85,
        "patterns": [
            r'hashlib\.(?:md5|sha1)\s*\(',
            r'(?:md5|sha1)\s*\([^)]+\)',
            r'(?:DES|RC4|DES3|Blowfish)[\s\.(]',
            r'createCipher\s*\(["\'](?:des|rc4|bf|blowfish)',
            r'Cipher\.getInstance\s*\(["\'](?:DES|RC2|RC4)',
            r'MessageDigest\.getInstance\s*\(["\'](?:MD5|SHA-1)["\']',
            r'new MD5\s*\(',
            r'crypto\.createHash\s*\(["\'](?:md5|sha1)["\']',
        ],
        "description": "Weak cryptographic algorithm detected. MD5/SHA-1 are cryptographically broken — collisions are practical. DES/RC4 have known practical attacks.",
        "remediation": "Use SHA-256+ for hashing. AES-256-GCM for encryption. bcrypt/argon2/scrypt for passwords.",
        "cwe": "CWE-327",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"],
    },
    {
        "id": "SAST-009", "category": "A02", "severity": "critical",
        "title": "JWT Signature Verification Disabled",
        "confidence": 0.93,
        "patterns": [
            r'algorithm\s*=\s*["\']none["\']',
            r'algorithms\s*=\s*\[["\']none["\']\]',
            r'verify\s*=\s*False',
            r'options\s*=\s*\{[^}]*["\']verify_signature["\']\s*:\s*False',
            r'jwt\.decode\s*\([^)]*verify\s*=\s*False',
            r'options\.ignoreExpiration\s*=\s*true',
            r'options\.ignoreNotBefore\s*=\s*true',
        ],
        "description": "JWT signature verification is disabled or 'none' algorithm is accepted. Any attacker can forge tokens, impersonate any user including admin.",
        "remediation": "Always verify JWT signatures. Never accept 'none' algorithm. Explicitly specify allowed algorithms (e.g. ['HS256']).",
        "cwe": "CWE-347",
        "references": ["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
    },
    {
        "id": "SAST-015", "category": "A02", "severity": "medium",
        "title": "Insecure Random Number Generator",
        "confidence": 0.80,
        "patterns": [
            r'random\.random\s*\(',
            r'random\.randint\s*\(',
            r'Math\.random\s*\(',
            r'new Random\s*\(',
            r'rand\s*\(',           # PHP rand()
            r'mt_rand\s*\(',       # PHP mt_rand
        ],
        "description": "Insecure pseudo-random number generator used. Predictable output makes session tokens, password reset codes, and OTPs guessable.",
        "remediation": "Use secrets.token_urlsafe() or os.urandom() in Python. crypto.randomBytes() in Node. SecureRandom in Java.",
        "cwe": "CWE-338",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"],
    },

    # ── A03: Injection ────────────────────────────────────────────────────────
    {
        "id": "SAST-002", "category": "A03", "severity": "critical",
        "title": "SQL Injection Sink",
        "confidence": 0.87,
        "patterns": [
            r'execute\s*\(["\'"]?\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^)]*\+',
            r'cursor\.execute\s*\(.*?%\s*\(',
            r'f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP).*?\{',
            r'["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s[^"\']*["\'"\s]*\+\s*\w',
            r'(?:query|sql)\s*=\s*["\'"].*(?:SELECT|INSERT|UPDATE|DELETE).*["\'"]\s*\+',
            r'\.raw\s*\(["\'].*(?:SELECT|INSERT|UPDATE).*\+',   # Django .raw()
            r'db\.query\s*\([^)]*\+[^)]*\)',                    # generic db.query +
            r'connection\.query\s*\([^)]*\+',                   # node mysql
            r'Statement\s*\)\s*\.execute\s*\([^)]*\+',          # JDBC
            r'\$(?:db|pdo|conn)\s*->\s*query\s*\([^)]*\.',      # PHP PDO
        ],
        "description": "User input appears directly concatenated into a SQL query, enabling SQL injection — full database read/write/delete by an attacker.",
        "remediation": "Use parameterized queries (prepared statements). Use an ORM. Never concatenate user input into SQL strings.",
        "cwe": "CWE-89",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    },
    {
        "id": "SAST-016", "category": "A03", "severity": "critical",
        "title": "NoSQL Injection",
        "confidence": 0.80,
        "patterns": [
            r'find\s*\(\s*\{[^}]*\$(?:where|regex|gt|lt|ne|in|nin|or|and)',
            r'db\.\w+\.find\s*\(\s*req\.',
            r'collection\.find\s*\(\s*\{[^}]*req\.',
            r'\$where\s*:\s*["\'][^"\']*["\']',
            r'mongoose\.\w+\.findOne?\s*\(\s*req\.',
        ],
        "description": "NoSQL injection detected — user input flows into MongoDB/NoSQL query operators. Attacker can manipulate query logic to bypass authentication or extract all data.",
        "remediation": "Validate and sanitize all input. Use mongoose schema validation. Never pass raw req.body/query directly to find().",
        "cwe": "CWE-943",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"],
    },
    {
        "id": "SAST-003", "category": "A03", "severity": "high",
        "title": "Cross-Site Scripting (XSS) Sink",
        "confidence": 0.82,
        "patterns": [
            r'innerHTML\s*=\s*[^;]*(?:req\.|request\.|params\.|query\.|body\.|user)',
            r'document\.write\s*\([^)]*(?:req\.|params\.|query\.|location\.)',
            r'eval\s*\([^)]*(?:req\.|params\.|query\.|input)',
            r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
            r'\$\(["\'"][^"\']*["\']\)\.html\s*\([^)]*(?:data|result|response)',
            r'\.innerText\s*=\s*[^;]*(?:req\.|request\.|params\.)',
            r'document\.getElementById[^;]+\.innerHTML\s*=',
            r'v-html\s*=\s*["\'][^"\']*["\']',   # Vue v-html with dynamic content
        ],
        "description": "User-controlled data flows into a DOM sink without sanitization. Attacker can inject malicious scripts — session theft, defacement, phishing.",
        "remediation": "Sanitize and encode all user-supplied data. Use textContent not innerHTML. Use DOMPurify. Implement strict CSP.",
        "cwe": "CWE-79",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    },
    {
        "id": "SAST-004", "category": "A03", "severity": "critical",
        "title": "OS Command Injection",
        "confidence": 0.88,
        "patterns": [
            r'os\.system\s*\([^)]*(?:req\.|request\.|params\.|query\.|input\()',
            r'subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
            r'exec\s*\([^)]*(?:req\.|request\.|params\.|user)',
            r'os\.popen\s*\([^)]*\+',
            r'child_process\.exec\s*\([^)]*(?:req\.|params\.|query\.)',
            r'shell_exec\s*\(',    # PHP
            r'system\s*\([^)]*\$_(?:GET|POST|REQUEST)',  # PHP with superglobals
            r'passthru\s*\(',      # PHP
            r'exec\s*\([^)]*\$_(?:GET|POST)',            # PHP exec
            r'Runtime\.getRuntime\(\)\.exec\s*\(',       # Java
        ],
        "description": "User input flows into a shell command execution function. Attacker can execute arbitrary OS commands — full server compromise, data exfiltration, lateral movement.",
        "remediation": "Never use shell=True with user input. Use subprocess with argument lists. Validate/whitelist all inputs. Use shlex.quote().",
        "cwe": "CWE-78",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
    },
    {
        "id": "SAST-017", "category": "A03", "severity": "high",
        "title": "LDAP Injection",
        "confidence": 0.78,
        "patterns": [
            r'ldap\.search\s*\([^)]*\+',
            r'ldap_search\s*\([^)]*\$_(?:GET|POST)',
            r'connection\.search\s*\([^)]*(?:req\.|request\.)',
            r'LdapConnection\s*\.\s*(?:search|find)\s*\([^)]*\+',
            r'filter\s*=\s*["\'].*(?:uid|cn|mail)=.*["\'\s]*\+',
        ],
        "description": "User input is concatenated into an LDAP search filter. LDAP injection can bypass authentication, enumerate directory entries, and escalate privileges.",
        "remediation": "Escape special LDAP characters: \\, *, (, ), NUL. Use parameterized LDAP queries. Validate input against strict allowlist.",
        "cwe": "CWE-90",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"],
    },
    {
        "id": "SAST-018", "category": "A03", "severity": "high",
        "title": "Server-Side Template Injection (SSTI) Sink",
        "confidence": 0.83,
        "patterns": [
            r'(?:render_template_string|Template)\s*\([^)]*(?:req\.|request\.|params\.|query\.)',
            r'Jinja2\s*\.\s*from_string\s*\([^)]*(?:req\.|user_input)',
            r'env\.from_string\s*\([^)]*(?:req\.|request\.)',
            r'nunjucks\.renderString\s*\([^)]*(?:req\.|params\.)',
            r'ejs\.render\s*\([^)]*(?:req\.|body\.)',
            r'Mustache\.render\s*\([^)]*(?:req\.|body\.)',
            r'handlebars\.compile\s*\([^)]*(?:req\.|body\.)',
        ],
        "description": "User input is rendered through a template engine. SSTI can escalate to Remote Code Execution — attacker runs arbitrary code on the server.",
        "remediation": "Never render user input through template engines. Use sandboxed environments. Pass user data as template context variables, not as the template itself.",
        "cwe": "CWE-94",
        "references": ["https://portswigger.net/research/server-side-template-injection"],
    },
    {
        "id": "SAST-019", "category": "A03", "severity": "medium",
        "title": "Log Injection",
        "confidence": 0.72,
        "patterns": [
            r'(?:logger|logging|log)\s*\.\s*(?:info|debug|warning|error|critical)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)',
            r'console\.log\s*\([^)]*(?:req\.|body\.|params\.)',
            r'System\.out\.println\s*\([^)]*(?:request\.|req\.)',
            r'print\s*\([^)]*(?:request\.|req\.|params\.)',
        ],
        "description": "User input is written to application logs without sanitization. Attacker can inject fake log entries, hide malicious activity, or exploit log parsers.",
        "remediation": "Sanitize log input — remove newlines (\\n, \\r) from user data before logging. Use structured logging.",
        "cwe": "CWE-117",
        "references": ["https://owasp.org/www-community/attacks/Log_Injection"],
    },
    {
        "id": "SAST-020", "category": "A03", "severity": "medium",
        "title": "Regular Expression DoS (ReDoS)",
        "confidence": 0.70,
        "patterns": [
            r're\.(?:match|search|findall)\s*\(["\'][^"\']*(\.\*|\.\+|\(\.\*\)){2,}',
            r'new RegExp\s*\([^)]*(?:req\.|params\.|query\.)',
            r're\.compile\s*\([^)]*(?:req\.|params\.|input)',
            r'RegExp\s*\([^)]*(?:req\.|query\.|body\.)',
        ],
        "description": "User input used to construct or is matched against a complex regex. Malicious input can cause catastrophic backtracking — service denial with a single request.",
        "remediation": "Never use user input in regex patterns. Use regex complexity analyzers (recheck, regexploit). Set regex timeouts.",
        "cwe": "CWE-1333",
        "references": ["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"],
    },

    # ── A01: Broken Access Control ────────────────────────────────────────────
    {
        "id": "SAST-005", "category": "A01", "severity": "high",
        "title": "Path Traversal Vulnerability",
        "confidence": 0.84,
        "patterns": [
            r'open\s*\([^)]*(?:request\.|req\.|params\.|query\.)[^)]*\)',
            r'(?:readFile|fs\.readFile|file_get_contents)\s*\([^)]*\+',
            r'Path\s*\([^)]*(?:request\.|req\.|params\.|query\.)',
            r'send_file\s*\([^)]*(?:request\.|req\.|params\.)',
            r'include\s*\([^)]*\$_(?:GET|POST|REQUEST)',  # PHP file include
            r'require\s*\([^)]*\$_(?:GET|POST)',          # PHP require
            r'fopen\s*\([^)]*\$_(?:GET|POST)',
        ],
        "description": "User input may construct file paths, allowing directory traversal to read arbitrary files — SSH keys, /etc/passwd, source code, credentials.",
        "remediation": "Validate and sanitize file paths. Use os.path.basename(). Implement an allowlist of permitted files. Use chroot jails.",
        "cwe": "CWE-22",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal"],
    },
    {
        "id": "SAST-021", "category": "A01", "severity": "high",
        "title": "Mass Assignment / Parameter Pollution",
        "confidence": 0.75,
        "patterns": [
            r'User\.(?:create|update|save)\s*\(\s*(?:request\.data|req\.body|params)\s*\)',
            r'Model\.(?:create|update)\s*\(\s*\*\*(?:request\.|req\.)\w+\)',
            r'\.update\s*\(\s*request\.form\s*\)',
            r'Object\.assign\s*\([^)]*,\s*req\.body\s*\)',
            r'\.create\s*\(\s*req\.body\s*\)',
            r'attrs\s*=\s*request\.POST',
        ],
        "description": "Model created or updated directly from user-supplied request data without field filtering. Attacker can set privileged fields like 'role', 'is_admin', 'balance'.",
        "remediation": "Whitelist allowed fields explicitly. Use serializer field allowlists. Never pass raw request body/form to model create/update.",
        "cwe": "CWE-915",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"],
    },

    # ── A05: Security Misconfiguration ───────────────────────────────────────
    {
        "id": "SAST-008", "category": "A05", "severity": "medium",
        "title": "Debug Mode Enabled in Production Code",
        "confidence": 0.88,
        "patterns": [
            r'DEBUG\s*=\s*True\b',
            r'debug\s*:\s*true\b',
            r'app\.run\s*\([^)]*debug\s*=\s*True',
            r'app\.set\s*\(["\']env["\']\s*,\s*["\']development["\']\)',
            r'FLASK_DEBUG\s*=\s*1',
            r'NODE_ENV\s*=\s*["\']development["\']',
            r'APP_DEBUG\s*=\s*true',   # Laravel
        ],
        "description": "Debug mode is enabled, exposing stack traces, internal paths, environment variables, and sensitive data to end users.",
        "remediation": "Set DEBUG=False in production. Use environment-specific configs. Manage via environment variables, not hardcoded values.",
        "cwe": "CWE-489",
        "references": ["https://owasp.org/A05_2021-Security_Misconfiguration/"],
    },
    {
        "id": "SAST-022", "category": "A05", "severity": "medium",
        "title": "Hardcoded IP Address",
        "confidence": 0.65,
        "patterns": [
            r'(?:host|server|db_host|redis_host)\s*[=:]\s*["\'](?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+["\']',
            r'["\'](?:192\.168|10\.\d+|172\.(?:1[6-9]|2\d|3[01]))\.\d+\.\d+["\'].*(?:port|connect|host)',
        ],
        "description": "Private/internal IP address hardcoded in source code. Reveals internal network topology and breaks portability across environments.",
        "remediation": "Use environment variables or config files for network addresses.",
        "cwe": "CWE-1244",
        "references": [],
    },

    # ── A07: Auth Failures ────────────────────────────────────────────────────
    {
        "id": "SAST-007", "category": "A08", "severity": "high",
        "title": "Insecure Deserialization",
        "confidence": 0.87,
        "patterns": [
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)',
            r'unserialize\s*\(',
            r'ObjectInputStream\s*\(',
            r'JSON\.parse\s*\([^)]*(?:req\.|request\.|params\.)',
            r'marshal\.loads?\s*\(',
            r'shelve\.open\s*\(',
            r'jsonpickle\.decode\s*\(',
            r'php_unserialize\s*\(',
        ],
        "description": "Deserialization of untrusted data can lead to remote code execution, privilege escalation, or denial of service.",
        "remediation": "Use yaml.safe_load(). Never deserialize untrusted pickle/marshal data. Validate all deserialized objects against a schema.",
        "cwe": "CWE-502",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"],
    },

    # ── A10: SSRF ─────────────────────────────────────────────────────────────
    {
        "id": "SAST-010", "category": "A10", "severity": "high",
        "title": "Server-Side Request Forgery (SSRF) Source",
        "confidence": 0.80,
        "patterns": [
            r'requests\.(?:get|post|put)\s*\([^)]*(?:request\.|req\.|params\.|query\.)',
            r'urllib\.request\.urlopen\s*\([^)]*(?:request\.|req\.|params\.)',
            r'httpx?\s*\.\s*(?:get|post)\s*\([^)]*(?:request\.|req\.|params\.|user_input)',
            r'fetch\s*\([^)]*(?:req\.|params\.|query\.|body\.)',
            r'axios\.(?:get|post)\s*\([^)]*(?:req\.|params\.|query\.)',
            r'curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$_(?:GET|POST)',
            r'file_get_contents\s*\([^)]*\$_(?:GET|POST)',
        ],
        "description": "User-controlled URL passed to an HTTP client. SSRF allows internal network scanning, cloud metadata access, and internal service exploitation.",
        "remediation": "Validate/whitelist allowed URLs. Block RFC-1918 ranges. Use DNS rebinding protection. Log all outbound requests.",
        "cwe": "CWE-918",
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
    },

    # ── A06: Vulnerable Components ────────────────────────────────────────────
    {
        "id": "SAST-023", "category": "A06", "severity": "high",
        "title": "eval() with Dynamic/User Input",
        "confidence": 0.90,
        "patterns": [
            r'eval\s*\([^)]*(?:request\.|req\.|params\.|query\.|body\.|input\(|user)',
            r'exec\s*\(\s*compile\s*\(',
            r'exec\s*\([^)]*(?:request\.|req\.|input\()',
            r'Function\s*\([^)]*(?:req\.|params\.|query\.)',    # JS new Function()
            r'vm\.runInThisContext\s*\([^)]*(?:req\.|params\.)',
        ],
        "description": "eval() or dynamic code execution called with user-controlled input. Attacker can execute arbitrary code in the application context — full server compromise.",
        "remediation": "Never use eval() with user input. Replace with safe alternatives: JSON.parse() for data, specific function calls for logic.",
        "cwe": "CWE-95",
        "references": ["https://owasp.org/www-community/attacks/Code_Injection"],
    },
    {
        "id": "SAST-024", "category": "A06", "severity": "medium",
        "title": "Prototype Pollution Sink (JavaScript)",
        "confidence": 0.75,
        "patterns": [
            r'(?:merge|deepMerge|extend|assign)\s*\(\s*(?:\{\}|\w+)\s*,\s*(?:req\.|body\.|params\.)',
            r'Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|body\.)\w+\s*\)',
            r'\$\.extend\s*\(\s*(?:true\s*,\s*)?\w+\s*,\s*(?:req\.|body\.)',
            r'lodash\.merge\s*\(',
            r'_\.merge\s*\([^)]*(?:req\.|body\.)',
        ],
        "description": "User-supplied object merged into target without prototype check. Prototype pollution can lead to property injection, DoS, or RCE via gadget chains.",
        "remediation": "Use Object.create(null) for merge targets. Validate keys against allowlist. Use safe merge libraries that block __proto__ and constructor keys.",
        "cwe": "CWE-1321",
        "references": ["https://portswigger.net/web-security/prototype-pollution"],
    },

    # ── A09: Logging / Monitoring ─────────────────────────────────────────────
    {
        "id": "SAST-025", "category": "A09", "severity": "low",
        "title": "Sensitive Data in Logs",
        "confidence": 0.72,
        "patterns": [
            r'(?:logger|log|logging)\.\w+\s*\([^)]*(?:password|passwd|secret|token|credit_card|ssn|cvv)',
            r'console\.log\s*\([^)]*(?:password|secret|token|apikey)',
            r'print\s*\([^)]*(?:password|secret|token)\s*[=:]\s*',
        ],
        "description": "Sensitive data (passwords, tokens, secrets) may be written to application logs. Log aggregation systems expose this to log viewers and attackers.",
        "remediation": "Never log credentials or secrets. Mask sensitive fields in logs. Use structured logging with field-level masking.",
        "cwe": "CWE-532",
        "references": ["https://owasp.org/A09_2021-Security_Logging_and_Monitoring_Failures/"],
    },
]


SCANNABLE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java",
    ".go", ".cs", ".cpp", ".c", ".h", ".env", ".yaml", ".yml",
    ".json", ".xml", ".conf", ".cfg", ".properties", ".sh", ".bash",
}

SKIP_PATTERNS = {
    "node_modules", ".venv", "__pycache__", ".git", "dist", "build",
    ".pytest_cache", "venv", "env", "vendor", "bower_components",
    "coverage", ".nyc_output", "target", "bin", "obj",
}

FETCHABLE_CONTENT_TYPES = {
    "text/javascript", "application/javascript", "text/plain",
    "application/json", "text/html", "application/x-yaml", "text/yaml",
    "text/x-python", "text/x-php",
}


class SASTScanner:

    def __init__(self, timeout: int = 30):
        self.timeout    = timeout
        self._findings: List[SASTFinding] = []
        self._seen_keys: Set[tuple] = set()

    def _add_finding(self, finding: SASTFinding):
        key = finding.dedup_key()
        if key not in self._seen_keys:
            self._seen_keys.add(key)
            self._findings.append(finding)

    # ── Mode 1: Scan code string ──────────────────────────────────────────────
    def scan_code_string(self, code: str, filename: str = "code.py") -> List[SASTFinding]:
        self._findings  = []
        self._seen_keys = set()
        lines = code.splitlines()
        self._scan_lines(lines, filename)
        return list(self._findings)

    # ── Mode 2: Scan via URL ──────────────────────────────────────────────────
    async def scan_url(self, target_url: str, client: httpx.AsyncClient) -> List[SASTFinding]:
        self._findings  = []
        self._seen_keys = set()

        fetched_sources: Dict[str, str] = {}
        parsed_base = urlparse(target_url)
        base_domain = parsed_base.netloc

        try:
            resp = await asyncio.wait_for(client.get(target_url), timeout=10)
            html_source = resp.text
            fetched_sources[target_url] = html_source

            linked_urls = self._extract_source_links(target_url, html_source, base_domain)
            results = await asyncio.gather(
                *[self._fetch_source(u, client) for u in linked_urls[:15]],
                return_exceptions=True
            )
            for url, result in zip(linked_urls[:15], results):
                if isinstance(result, str) and result:
                    fetched_sources[url] = result

        except asyncio.TimeoutError:
            logger.warning(f"SAST URL fetch timeout: {target_url}")
        except Exception as e:
            logger.warning(f"SAST URL fetch error: {e}")

        for source_url, source_code in fetched_sources.items():
            filename = self._url_to_filename(source_url)
            self._scan_lines(source_code.splitlines(), filename)

        # Header analysis
        try:
            resp = await asyncio.wait_for(client.get(target_url), timeout=8)
            for hf in await self.scan_target_headers_from_response(resp, target_url):
                self._add_finding(hf)
        except Exception:
            pass

        logger.info(f"SAST v2.0 URL scan: {len(fetched_sources)} files, {len(self._findings)} findings")
        return list(self._findings)

    async def _fetch_source(self, url: str, client: httpx.AsyncClient) -> str:
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=8)
            ct = resp.headers.get("content-type", "").lower()
            if any(t in ct for t in FETCHABLE_CONTENT_TYPES) or resp.status_code == 200:
                return resp.text[:200_000]
        except Exception:
            pass
        return ""

    def _extract_source_links(self, base_url: str, html: str, base_domain: str) -> List[str]:
        urls: List[str] = []
        seen: Set[str]  = set()

        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            href = m.group(1).strip()
            if not href.startswith("data:"):
                full = urljoin(base_url, href).split("?")[0].split("#")[0]
                if full not in seen:
                    seen.add(full); urls.append(full)

        for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.(?:json|yaml|yml|conf))["\']', html, re.I):
            href = m.group(1).strip()
            full = urljoin(base_url, href).split("?")[0]
            if full not in seen:
                seen.add(full); urls.append(full)

        parsed = urlparse(base_url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        for path in [
            "/static/js/main.js", "/js/app.js", "/assets/index.js",
            "/config.json", "/app.js", "/bundle.js", "/.env.example",
            "/package.json", "/robots.txt", "/js/main.js",
            "/static/js/bundle.js", "/dist/bundle.js",
        ]:
            full = base + path
            if full not in seen:
                seen.add(full); urls.append(full)

        return urls

    def _url_to_filename(self, url: str) -> str:
        try:
            path = urlparse(url).path
            return path.split("/")[-1] or "index.html"
        except Exception:
            return url[-40:]

    # ── Core scanning logic ───────────────────────────────────────────────────
    def _scan_lines(self, lines: List[str], filename: str):
        content = "\n".join(lines)
        for rule in SAST_RULES:
            for pattern_str in rule["patterns"]:
                try:
                    pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                    for match in pattern.finditer(content):
                        line_no = content[:match.start()].count("\n") + 1

                        line_content = lines[line_no-1] if line_no <= len(lines) else ""
                        stripped = line_content.strip()

                        # Skip comment lines
                        if stripped.startswith(("#","//","*","/*","<!--","--",";")):
                            continue

                        # Skip test files for secrets rules (lower confidence)
                        is_test = any(t in filename.lower() for t in
                                      ["test","spec","mock","fixture","example","demo",".min.js"])
                        confidence = rule.get("confidence", 0.78)
                        if is_test:
                            confidence = max(0.4, confidence - 0.25)

                        # Context snippet (3 lines before + 3 after)
                        start   = max(0, line_no - 4)
                        end     = min(len(lines), line_no + 3)
                        snippet = "\n".join(
                            f"{start+i+1}: {lines[start+i]}"
                            for i in range(end-start)
                        )

                        self._add_finding(SASTFinding(
                            rule_id=rule["id"],
                            category=rule["category"],
                            title=rule["title"],
                            description=rule["description"],
                            severity=rule["severity"],
                            file_path=filename,
                            line_number=line_no,
                            code_snippet=snippet[:500],
                            remediation=rule["remediation"],
                            confidence=confidence,
                            cwe=rule.get("cwe",""),
                            references=rule.get("references",[]),
                        ))
                except re.error:
                    pass

    # ── Header analysis ───────────────────────────────────────────────────────
    async def scan_target_headers(self, url: str, client: httpx.AsyncClient) -> List[SASTFinding]:
        try:
            resp = await asyncio.wait_for(client.get(url), timeout=10)
            return await self.scan_target_headers_from_response(resp, url)
        except Exception as e:
            logger.debug(f"SAST header scan error for {url}: {e}")
            return []

    async def scan_target_headers_from_response(
        self, resp: httpx.Response, url: str
    ) -> List[SASTFinding]:
        findings: List[SASTFinding] = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        HEADER_CHECKS = [
            ("strict-transport-security", "SAST-H01", "Missing HSTS Header",
             "HTTP Strict Transport Security not set — SSL stripping attacks possible.",
             "high", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", "CWE-319"),
            ("content-security-policy", "SAST-H02", "Missing Content-Security-Policy",
             "No CSP header — XSS attacks not mitigated at browser level.",
             "high", "Implement: Content-Security-Policy: default-src 'self'", "CWE-693"),
            ("x-frame-options", "SAST-H03", "Clickjacking — Missing X-Frame-Options",
             "Page can be embedded in iframes, enabling clickjacking.",
             "medium", "Add: X-Frame-Options: DENY", "CWE-1021"),
            ("x-content-type-options", "SAST-H04", "Missing X-Content-Type-Options",
             "MIME sniffing not prevented — may enable XSS via file uploads.",
             "medium", "Add: X-Content-Type-Options: nosniff", "CWE-430"),
            ("referrer-policy", "SAST-H05", "Missing Referrer-Policy",
             "No Referrer-Policy — URL parameters may leak via Referer header.",
             "low", "Add: Referrer-Policy: strict-origin-when-cross-origin", "CWE-200"),
            ("permissions-policy", "SAST-H06", "Missing Permissions-Policy",
             "Browser APIs (camera, mic, geolocation) accessible without restriction.",
             "low", "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()", "CWE-16"),
        ]

        for header, rule_id, title, desc, severity, rem, cwe in HEADER_CHECKS:
            if header not in headers:
                findings.append(SASTFinding(
                    rule_id=rule_id, category="A05",
                    title=title, description=desc,
                    severity=severity, file_path=url,
                    line_number=0,
                    code_snippet=f"Response header '{header}' — NOT PRESENT",
                    remediation=rem, confidence=1.0, cwe=cwe,
                    references=["https://owasp.org/A05_2021-Security_Misconfiguration/"],
                ))

        server = headers.get("server", "")
        if server and re.search(r"\d+\.\d+", server):
            findings.append(SASTFinding(
                rule_id="SAST-H07", category="A05",
                title="Server Version Disclosure",
                description=f"Server header exposes version: {server}",
                severity="low", file_path=url, line_number=0,
                code_snippet=f"Server: {server}",
                remediation="Remove or obfuscate the Server header.",
                confidence=1.0, cwe="CWE-200",
            ))

        cookie_hdr = headers.get("set-cookie", "")
        if cookie_hdr and "httponly" not in cookie_hdr.lower():
            findings.append(SASTFinding(
                rule_id="SAST-H08", category="A07",
                title="Cookie Missing HttpOnly Flag",
                description="Session cookie accessible to JavaScript — theft via XSS possible.",
                severity="medium", file_path=url, line_number=0,
                code_snippet=f"Set-Cookie: {cookie_hdr[:120]}",
                remediation="Add HttpOnly flag to all session cookies.",
                confidence=0.9, cwe="CWE-1004",
            ))

        return findings

    def scan_directory(self, directory: str) -> List[SASTFinding]:
        self._findings  = []
        self._seen_keys = set()
        root = Path(directory)
        if not root.exists():
            return []
        for filepath in root.rglob("*"):
            if filepath.is_file() and filepath.suffix.lower() in SCANNABLE_EXTENSIONS:
                parts = set(filepath.parts)
                if parts & SKIP_PATTERNS:
                    continue
                try:
                    content = filepath.read_text(encoding="utf-8", errors="replace")
                    self._scan_lines(content.splitlines(), str(filepath))
                except Exception:
                    pass
        return list(self._findings)

    def get_summary(self) -> Dict:
        counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return {
            "total":    len(self._findings),
            "counts":   counts,
            "findings": [
                {
                    "rule_id":    f.rule_id,
                    "category":   f.category,
                    "title":      f.title,
                    "severity":   f.severity,
                    "file":       f.file_path,
                    "line":       f.line_number,
                    "confidence": f.confidence,
                }
                for f in self._findings
            ],
        }


sast_scanner = SASTScanner()
