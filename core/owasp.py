"""
SentinelAI - OWASP Top 10 (2021) Mapping
Maps every finding title/type to its OWASP category.
"""

# Full OWASP Top 10 2021 reference
OWASP_CATEGORIES = {
    "A01": {
        "id":    "A01:2021",
        "name":  "Broken Access Control",
        "url":   "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "desc":  "Restrictions on what authenticated users are allowed to do are not properly enforced.",
    },
    "A02": {
        "id":    "A02:2021",
        "name":  "Cryptographic Failures",
        "url":   "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "desc":  "Failures related to cryptography which often lead to sensitive data exposure.",
    },
    "A03": {
        "id":    "A03:2021",
        "name":  "Injection",
        "url":   "https://owasp.org/Top10/A03_2021-Injection/",
        "desc":  "User-supplied data is not validated, filtered, or sanitized by the application.",
    },
    "A04": {
        "id":    "A04:2021",
        "name":  "Insecure Design",
        "url":   "https://owasp.org/Top10/A04_2021-Insecure_Design/",
        "desc":  "Missing or ineffective control design — flaws in architecture and design.",
    },
    "A05": {
        "id":    "A05:2021",
        "name":  "Security Misconfiguration",
        "url":   "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "desc":  "Missing security hardening, unnecessary features enabled, insecure default configurations.",
    },
    "A06": {
        "id":    "A06:2021",
        "name":  "Vulnerable & Outdated Components",
        "url":   "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        "desc":  "Components with known vulnerabilities used without proper patch management.",
    },
    "A07": {
        "id":    "A07:2021",
        "name":  "Identification & Authentication Failures",
        "url":   "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
        "desc":  "Weaknesses in authentication and session management allow attackers to compromise credentials.",
    },
    "A08": {
        "id":    "A08:2021",
        "name":  "Software & Data Integrity Failures",
        "url":   "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        "desc":  "Code and infrastructure without integrity protection — insecure deserialization, unsigned webhooks.",
    },
    "A09": {
        "id":    "A09:2021",
        "name":  "Security Logging & Monitoring Failures",
        "url":   "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
        "desc":  "Insufficient logging and monitoring prevents detection of breaches.",
    },
    "A10": {
        "id":    "A10:2021",
        "name":  "Server-Side Request Forgery",
        "url":   "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        "desc":  "Application fetches remote resources without validating the user-supplied URL.",
    },
}


# ── Mapping table: keywords in finding title/description → OWASP category ─
# Order matters — more specific patterns first
OWASP_RULES = [
    # A03 — Injection
    (["sql injection", "unsanitized", "raw sql", "string concatenation in query",
      "eval()", "use of eval", "code injection", "command injection",
      "template injection", "xpath injection"], "A03"),

    # A02 — Cryptographic Failures
    (["hardcoded secret", "exposed api key", "api key", "hardcoded password",
      "hardcoded token", "password in code", "secret in code",
      "weak hash", "md5", "sha1", "sha-1", "weak cipher", "ecb mode",
      "insecure random", "predictable random", "weak random",
      "plaintext password", "password stored", "unencrypted",
      "ssl", "verify=false", "certificate", "tls"], "A02"),

    # A07 — Auth Failures
    (["login bypass", "authentication bypass", "auth bypass",
      "always-true condition", "privilege escalation", "role check",
      "session fixation", "session hijacking", "broken authentication",
      "missing authentication", "weak password", "brute force",
      "account enumeration", "password comparison"], "A07"),

    # A01 — Broken Access Control
    (["unauthenticated route", "missing authorization", "unauthorized access",
      "access control", "idor", "insecure direct object", "path traversal",
      "directory traversal", "broken access", "missing login_required",
      "privilege", "admin bypass"], "A01"),

    # A05 — Security Misconfiguration
    (["debug mode", "debug=true", "cors", "wildcard origin",
      "missing header", "security header", "x-frame", "x-content-type",
      "hsts", "content security policy", "csp", "clickjacking",
      "cookie", "httponly", "secure flag", "session cookie",
      "default credential", "exposed stack trace", "verbose error"], "A05"),

    # A06 — Vulnerable Components
    (["vulnerable dependency", "outdated", "cve-", "known vulnerability",
      "unpinned dependency", "insecure version", "deprecated"], "A06"),

    # A08 — Integrity Failures
    (["webhook", "unsigned", "csrf", "cross-site request forgery",
      "deserialization", "pickle", "yaml.load", "integrity",
      "supply chain", "tampered"], "A08"),

    # A04 — Insecure Design
    (["insecure random", "weak reset token", "no rate limit",
      "business logic", "race condition", "mass assignment",
      "predictable", "enumerable"], "A04"),

    # A10 — SSRF
    (["ssrf", "server-side request", "unvalidated url",
      "open redirect", "url redirect", "fetch url"], "A10"),

    # A09 — Logging failures
    (["no logging", "audit log", "missing log", "insufficient log",
      "monitoring"], "A09"),
]


def get_owasp(finding_title: str, finding_desc: str = "") -> dict:
    """
    Return the OWASP category dict for a given finding.
    Returns None if no match found.
    """
    combined = (finding_title + " " + finding_desc).lower()

    for keywords, category_key in OWASP_RULES:
        if any(kw in combined for kw in keywords):
            return OWASP_CATEGORIES[category_key]

    return None


def get_owasp_id(finding_title: str, finding_desc: str = "") -> str:
    """Return just the OWASP ID string e.g. 'A03:2021' or empty string."""
    cat = get_owasp(finding_title, finding_desc)
    return cat["id"] if cat else ""


def get_owasp_name(finding_title: str, finding_desc: str = "") -> str:
    """Return 'A03:2021 — Injection' style string or empty string."""
    cat = get_owasp(finding_title, finding_desc)
    if cat:
        return f"{cat['id']} — {cat['name']}"
    return ""


def annotate_findings(findings: list) -> list:
    """
    Add owasp_id and owasp_name to each Finding object in place.
    Call this after all agents have run, before building the report.
    """
    for f in findings:
        cat = get_owasp(f.title, f.description or "")
        if cat:
            f.owasp_id   = cat["id"]
            f.owasp_name = cat["name"]
            f.owasp_url  = cat["url"]
        else:
            f.owasp_id   = ""
            f.owasp_name = ""
            f.owasp_url  = ""
    return findings
