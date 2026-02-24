"""
SentinelAI - Agent G: CORS & Security Headers Auditor
Detects missing or misconfigured security headers and CORS policies
in Flask/FastAPI applications.
"""
import ast
import re
from typing import List
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Security headers that should be present
REQUIRED_SECURITY_HEADERS = {
    "X-Content-Type-Options": (
        Severity.MEDIUM,
        "Prevents MIME-type sniffing attacks.",
        "Add: response.headers['X-Content-Type-Options'] = 'nosniff'",
        "CWE-693"
    ),
    "X-Frame-Options": (
        Severity.MEDIUM,
        "Prevents clickjacking by controlling iframe embedding.",
        "Add: response.headers['X-Frame-Options'] = 'DENY' or 'SAMEORIGIN'",
        "CWE-1021"
    ),
    "Strict-Transport-Security": (
        Severity.HIGH,
        "Enforces HTTPS connections (HSTS). Without this, users can be downgraded to HTTP.",
        "Add: response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
        "CWE-319"
    ),
    "Content-Security-Policy": (
        Severity.HIGH,
        "Controls which resources the browser can load, preventing XSS attacks.",
        "Add a Content-Security-Policy header to restrict script/style sources.",
        "CWE-79"
    ),
    "X-XSS-Protection": (
        Severity.LOW,
        "Enables browser XSS filter (legacy browsers).",
        "Add: response.headers['X-XSS-Protection'] = '1; mode=block'",
        "CWE-79"
    ),
    "Referrer-Policy": (
        Severity.LOW,
        "Controls how much referrer info is sent with requests.",
        "Add: response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
        "CWE-200"
    ),
}

# Dangerous CORS patterns
CORS_DANGEROUS_PATTERNS = [
    (r'CORS\s*\(\s*app\s*\)',
     "Wildcard CORS Configuration",
     "flask_cors.CORS(app) with no origins specified allows ALL origins.",
     Severity.HIGH, "CWE-942"),

    (r'origins\s*=\s*["\']?\*["\']?',
     "Wildcard CORS Origin (*)",
     "Setting CORS origins to '*' allows any website to make cross-origin requests to your API.",
     Severity.HIGH, "CWE-942"),

    (r'Access-Control-Allow-Origin.*\*',
     "Wildcard Access-Control-Allow-Origin Header",
     "Setting Access-Control-Allow-Origin: * is dangerous for authenticated APIs.",
     Severity.HIGH, "CWE-942"),

    (r'supports_credentials\s*=\s*True.*origins\s*=\s*["\']?\*',
     "CORS Credentials with Wildcard Origin",
     "Combining credentials=True with wildcard origins is a critical misconfiguration.",
     Severity.CRITICAL, "CWE-942"),

    (r'Access-Control-Allow-Credentials.*true',
     "CORS Allow-Credentials Enabled",
     "Access-Control-Allow-Credentials: true should only be used with specific trusted origins, never with *.",
     Severity.MEDIUM, "CWE-942"),
]


class CORSAndHeadersAuditor:
    """Agent G: Audits CORS configuration and security headers."""

    AGENT_NAME = "Agent G - CORS & Headers Auditor"

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []
        for analysis in analyses:
            findings.extend(self._scan_cors(analysis))
            findings.extend(self._scan_security_headers(analysis))
            findings.extend(self._scan_flask_config(analysis))
        return findings

    def _scan_cors(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        source = analysis.source_code
        lines = source.splitlines()

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in CORS_DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation=(
                            "Specify explicit trusted origins instead of wildcards:\n"
                            "CORS(app, origins=['https://yourdomain.com'])\n"
                            "Never use '*' with credentials=True."
                        ),
                        cwe_id=cwe
                    ))
                    break

        return findings

    def _scan_security_headers(self, analysis: FileAnalysis) -> List[Finding]:
        """Check if security headers are set anywhere in the codebase."""
        findings = []
        source = analysis.source_code

        # Check if this file has any response/header manipulation
        has_responses = any(kw in source for kw in
                           ["response", "make_response", "after_request", "Response"])
        if not has_responses:
            return findings

        # Check which required headers are missing
        for header_name, (severity, desc, rec, cwe) in REQUIRED_SECURITY_HEADERS.items():
            if header_name not in source:
                findings.append(Finding(
                    agent=self.AGENT_NAME,
                    title=f"Missing Security Header: {header_name}",
                    description=(
                        f"The '{header_name}' security header is not set in this file. "
                        f"{desc}"
                    ),
                    severity=severity,
                    filepath=analysis.filepath,
                    lineno=None,
                    code_snippet=None,
                    recommendation=(
                        f"{rec}\n\n"
                        f"Best practice: Set all security headers globally using an "
                        f"@app.after_request decorator:\n\n"
                        f"@app.after_request\n"
                        f"def set_security_headers(response):\n"
                        f"    response.headers['{header_name}'] = '...'\n"
                        f"    return response"
                    ),
                    cwe_id=cwe
                ))

        return findings

    def _scan_flask_config(self, analysis: FileAnalysis) -> List[Finding]:
        """Scan Flask-specific security misconfigurations."""
        findings = []
        source = analysis.source_code
        lines = source.splitlines()

        flask_security_checks = [
            # Session cookie security
            (r"SESSION_COOKIE_SECURE\s*=\s*False",
             "Insecure Session Cookie (SESSION_COOKIE_SECURE=False)",
             "Session cookies sent over HTTP can be intercepted.",
             Severity.HIGH, "CWE-614"),

            (r"SESSION_COOKIE_HTTPONLY\s*=\s*False",
             "Session Cookie Accessible via JavaScript (HTTPONLY=False)",
             "Cookies without HttpOnly flag can be stolen via XSS.",
             Severity.HIGH, "CWE-1004"),

            (r"SESSION_COOKIE_SAMESITE\s*=\s*None",
             "SameSite=None Cookie Configuration",
             "SameSite=None allows cross-site request forgery attacks.",
             Severity.MEDIUM, "CWE-352"),

            # WTF CSRF
            (r"WTF_CSRF_ENABLED\s*=\s*False",
             "CSRF Protection Disabled",
             "Disabling CSRF protection exposes all forms to cross-site request forgery.",
             Severity.CRITICAL, "CWE-352"),

            # Secret key issues
            (r"SECRET_KEY\s*=\s*[\"'][\w]{1,8}[\"']",
             "Weak Flask Secret Key",
             "The SECRET_KEY is too short. A short key can be brute-forced, compromising all sessions.",
             Severity.HIGH, "CWE-331"),
        ]

        for lineno, line in enumerate(lines, 1):
            for pattern, title, desc, severity, cwe in flask_security_checks:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=desc,
                        severity=severity,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation="Review Flask security configuration. See: https://flask.palletsprojects.com/en/latest/security/",
                        cwe_id=cwe
                    ))
                    break

        return findings
