"""
SentinelAI - OWASP Top 10 (2021) Mapping
Primary method: CWE-to-OWASP deterministic mapping
Fallback: keyword matching on title/description
"""

OWASP_CATEGORIES = {
    "A01": {"id": "A01:2021", "name": "Broken Access Control",
             "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
    "A02": {"id": "A02:2021", "name": "Cryptographic Failures",
             "url": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"},
    "A03": {"id": "A03:2021", "name": "Injection",
             "url": "https://owasp.org/Top10/A03_2021-Injection/"},
    "A04": {"id": "A04:2021", "name": "Insecure Design",
             "url": "https://owasp.org/Top10/A04_2021-Insecure_Design/"},
    "A05": {"id": "A05:2021", "name": "Security Misconfiguration",
             "url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"},
    "A06": {"id": "A06:2021", "name": "Vulnerable & Outdated Components",
             "url": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"},
    "A07": {"id": "A07:2021", "name": "Identification & Authentication Failures",
             "url": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"},
    "A08": {"id": "A08:2021", "name": "Software & Data Integrity Failures",
             "url": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"},
    "A09": {"id": "A09:2021", "name": "Security Logging & Monitoring Failures",
             "url": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"},
    "A10": {"id": "A10:2021", "name": "Server-Side Request Forgery",
             "url": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"},
}

# ── PRIMARY: CWE -> OWASP deterministic mapping ────────────────────────────
# Source: https://owasp.org/Top10/A00_2021_How_to_start_an_AppSec_Program_with_the_OWASP_Top_10/
CWE_TO_OWASP = {
    # A01 Broken Access Control
    "CWE-22": "A01", "CWE-23": "A01", "CWE-35": "A01", "CWE-59": "A01",
    "CWE-200": "A01", "CWE-201": "A01", "CWE-219": "A01", "CWE-264": "A01",
    "CWE-275": "A01", "CWE-276": "A01", "CWE-284": "A01", "CWE-285": "A01",
    "CWE-352": "A01", "CWE-359": "A01", "CWE-377": "A01", "CWE-402": "A01",
    "CWE-425": "A01", "CWE-441": "A01", "CWE-497": "A01", "CWE-538": "A01",
    "CWE-540": "A01", "CWE-548": "A01", "CWE-552": "A01", "CWE-566": "A01",
    "CWE-601": "A01", "CWE-639": "A01", "CWE-651": "A01", "CWE-668": "A01",
    "CWE-706": "A01", "CWE-862": "A01", "CWE-863": "A01", "CWE-913": "A01",
    "CWE-922": "A01", "CWE-1275": "A01",
    # A02 Cryptographic Failures
    "CWE-261": "A02", "CWE-296": "A02", "CWE-310": "A02", "CWE-319": "A02",
    "CWE-321": "A02", "CWE-322": "A02", "CWE-323": "A02", "CWE-324": "A02",
    "CWE-325": "A02", "CWE-326": "A02", "CWE-327": "A02", "CWE-328": "A02",
    "CWE-329": "A02", "CWE-330": "A02", "CWE-331": "A02", "CWE-335": "A02",
    "CWE-336": "A02", "CWE-337": "A02", "CWE-338": "A02", "CWE-339": "A02",
    "CWE-340": "A02", "CWE-347": "A02", "CWE-523": "A02", "CWE-720": "A02",
    "CWE-757": "A02", "CWE-759": "A02", "CWE-760": "A02", "CWE-780": "A02",
    "CWE-818": "A02", "CWE-916": "A02",
    # A03 Injection
    "CWE-20": "A03",  "CWE-74": "A03",  "CWE-75": "A03",  "CWE-77": "A03",
    "CWE-78": "A03",  "CWE-79": "A03",  "CWE-80": "A03",  "CWE-83": "A03",
    "CWE-87": "A03",  "CWE-88": "A03",  "CWE-89": "A03",  "CWE-90": "A03",
    "CWE-91": "A03",  "CWE-93": "A03",  "CWE-94": "A03",  "CWE-95": "A03",
    "CWE-96": "A03",  "CWE-97": "A03",  "CWE-98": "A03",  "CWE-99": "A03",
    "CWE-100": "A03", "CWE-113": "A03", "CWE-116": "A03", "CWE-138": "A03",
    "CWE-184": "A03", "CWE-470": "A03", "CWE-471": "A03", "CWE-564": "A03",
    "CWE-610": "A03", "CWE-643": "A03", "CWE-644": "A03", "CWE-652": "A03",
    "CWE-917": "A03",
    # A04 Insecure Design
    "CWE-73": "A04", "CWE-183": "A04", "CWE-209": "A04", "CWE-213": "A04",
    "CWE-235": "A04", "CWE-256": "A04", "CWE-257": "A04", "CWE-266": "A04",
    "CWE-269": "A04", "CWE-280": "A04", "CWE-311": "A04", "CWE-312": "A04",
    "CWE-313": "A04", "CWE-316": "A04", "CWE-419": "A04", "CWE-430": "A04",
    "CWE-434": "A04", "CWE-444": "A04", "CWE-451": "A04", "CWE-472": "A04",
    "CWE-501": "A04", "CWE-522": "A04", "CWE-525": "A04", "CWE-539": "A04",
    "CWE-579": "A04", "CWE-598": "A04", "CWE-602": "A04", "CWE-642": "A04",
    "CWE-646": "A04", "CWE-650": "A04", "CWE-653": "A04", "CWE-656": "A04",
    "CWE-657": "A04", "CWE-799": "A04",
    # A05 Security Misconfiguration
    "CWE-2": "A05",   "CWE-11": "A05",  "CWE-13": "A05",  "CWE-15": "A05",
    "CWE-16": "A05",  "CWE-260": "A05", "CWE-315": "A05", "CWE-520": "A05",
    "CWE-526": "A05", "CWE-537": "A05", "CWE-541": "A05", "CWE-547": "A05",
    "CWE-611": "A05", "CWE-614": "A05", "CWE-756": "A05", "CWE-776": "A05",
    "CWE-942": "A05", "CWE-1021": "A05","CWE-1173": "A05",
    # A06 Vulnerable & Outdated Components
    "CWE-937": "A06", "CWE-1035": "A06", "CWE-1104": "A06",
    # A07 Auth & Identity
    "CWE-255": "A07", "CWE-259": "A07", "CWE-287": "A07", "CWE-288": "A07",
    "CWE-290": "A07", "CWE-294": "A07", "CWE-295": "A07", "CWE-297": "A07",
    "CWE-300": "A07", "CWE-302": "A07", "CWE-304": "A07", "CWE-305": "A07",
    "CWE-306": "A07", "CWE-307": "A07", "CWE-346": "A07", "CWE-384": "A07",
    "CWE-521": "A07", "CWE-613": "A07", "CWE-620": "A07", "CWE-640": "A07",
    "CWE-798": "A07", "CWE-940": "A07", "CWE-1216": "A07",
    # A08 Software & Data Integrity
    "CWE-345": "A08", "CWE-353": "A08", "CWE-426": "A08", "CWE-494": "A08",
    "CWE-502": "A08", "CWE-565": "A08", "CWE-784": "A08", "CWE-829": "A08",
    "CWE-830": "A08", "CWE-912": "A08",
    # A09 Logging
    "CWE-117": "A09", "CWE-223": "A09", "CWE-532": "A09", "CWE-778": "A09",
    # A10 SSRF
    "CWE-918": "A10",
}

# ── FALLBACK: keyword matching ─────────────────────────────────────────────
KEYWORD_RULES = [
    (["sql injection", "unsanitized", "raw sql", "eval()", "code injection",
      "command injection", "template injection"], "A03"),
    (["hardcoded secret", "api key", "hardcoded password", "hardcoded token",
      "weak hash", "md5", "sha1", "insecure random", "predictable random",
      "plaintext password", "ssl", "verify=false", "certificate",
      "in git history", "connection string", "aws key", "database url",
      "credentials in git"], "A02"),
    (["login bypass", "authentication bypass", "auth bypass", "always-true",
      "privilege escalation", "broken authentication", "password comparison"], "A07"),
    (["unauthenticated route", "missing authorization", "access control",
      "path traversal", "idor", "broken access"], "A01"),
    (["debug mode", "cors", "wildcard origin", "missing header", "security header",
      "x-frame", "hsts", "content security policy", "cookie", "httponly"], "A05"),
    (["vulnerable dependency", "outdated", "cve-", "known vulnerability",
      "unpinned dependency", "insecure version"], "A06"),
    (["webhook", "unsigned", "csrf", "deserialization", "pickle"], "A08"),
    (["no rate limit", "weak reset token", "race condition"], "A04"),
    (["ssrf", "server-side request", "unvalidated url", "open redirect"], "A10"),
    (["no logging", "audit log", "missing log"], "A09"),
]


def get_owasp(finding_title: str, finding_desc: str = "", cwe_id: str = "") -> dict:
    """
    Return OWASP category. 
    Priority: CWE mapping (deterministic) -> keyword matching (fallback)
    """
    # PRIMARY: CWE-to-OWASP mapping (deterministic)
    if cwe_id:
        cwe_upper = cwe_id.strip().upper()
        if cwe_upper in CWE_TO_OWASP:
            cat_key = CWE_TO_OWASP[cwe_upper]
            return OWASP_CATEGORIES[cat_key]

    # FALLBACK: keyword matching
    combined = (finding_title + " " + finding_desc).lower()
    for keywords, cat_key in KEYWORD_RULES:
        if any(kw in combined for kw in keywords):
            return OWASP_CATEGORIES[cat_key]

    return None


def get_owasp_id(title: str, desc: str = "", cwe: str = "") -> str:
    cat = get_owasp(title, desc, cwe)
    return cat["id"] if cat else ""


def annotate_findings(findings: list) -> list:
    """Add owasp_id, owasp_name, owasp_url to every Finding in-place."""
    for f in findings:
        cwe = getattr(f, "cwe_id", "") or ""
        cat = get_owasp(f.title, getattr(f, "description", "") or "", cwe)
        if cat:
            f.owasp_id   = cat["id"]
            f.owasp_name = cat["name"]
            f.owasp_url  = cat["url"]
        else:
            f.owasp_id   = ""
            f.owasp_name = ""
            f.owasp_url  = ""
    return findings
