"""
SentinelAI - Agent E: Dependency & CVE Scanner
Scans requirements.txt and setup.py for packages with known vulnerabilities
using the PyPI Advisory Database (OSV.dev API).
"""
import json
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Optional
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Known vulnerable packages (offline fallback database)
# Format: package_name: [(affected_version_pattern, cve, severity, description)]
OFFLINE_VULN_DB = {
    "flask": [
        ("<=0.12.4", "CVE-2018-1000656", Severity.HIGH,
         "Flask before 0.12.5 is vulnerable to Denial of Service via malicious JSON data."),
    ],
    "django": [
        ("<=2.2.27", "CVE-2022-28346", Severity.CRITICAL,
         "Django SQL injection vulnerability in QuerySet.annotate()."),
        ("<=3.2.12", "CVE-2022-22818", Severity.MEDIUM,
         "Django XSS vulnerability via {% debug %} template tag."),
    ],
    "requests": [
        ("<=2.19.1", "CVE-2018-18074", Severity.MEDIUM,
         "Requests library sends HTTP Authorization header to redirected hosts."),
    ],
    "pillow": [
        ("<=9.0.1", "CVE-2022-22817", Severity.CRITICAL,
         "Pillow PIL.ImageMath.eval allows arbitrary code execution."),
    ],
    "pyyaml": [
        ("<=5.4", "CVE-2020-14343", Severity.CRITICAL,
         "PyYAML arbitrary code execution via yaml.load() without Loader."),
    ],
    "cryptography": [
        ("<=3.3.1", "CVE-2020-36242", Severity.HIGH,
         "cryptography package buffer overflow in symmetric encryption."),
    ],
    "urllib3": [
        ("<=1.26.4", "CVE-2021-33503", Severity.HIGH,
         "urllib3 ReDoS vulnerability in URL parsing."),
    ],
    "sqlalchemy": [
        ("<=1.3.23", "CVE-2019-7164", Severity.HIGH,
         "SQLAlchemy SQL injection via order_by() parameter."),
    ],
    "paramiko": [
        ("<=2.4.1", "CVE-2018-1000805", Severity.CRITICAL,
         "Paramiko authentication bypass vulnerability."),
    ],
    "jinja2": [
        ("<=2.11.2", "CVE-2020-28493", Severity.MEDIUM,
         "Jinja2 ReDoS vulnerability in urlize filter."),
    ],
    "werkzeug": [
        ("<=2.0.0", "CVE-2023-25577", Severity.HIGH,
         "Werkzeug multipart data parsing DoS vulnerability."),
    ],
    "numpy": [
        ("<=1.16.0", "CVE-2019-6446", Severity.HIGH,
         "NumPy pickle deserialization vulnerability via np.load()."),
    ],
}


def parse_version(version_str: str) -> tuple:
    """Parse version string into comparable tuple."""
    try:
        clean = re.sub(r'[^0-9.]', '', version_str)
        parts = clean.split('.')
        return tuple(int(p) for p in parts[:3] if p)
    except Exception:
        return (0, 0, 0)


def version_affected(installed: str, constraint: str) -> bool:
    """Check if installed version satisfies a vulnerability constraint."""
    try:
        op_match = re.match(r'([<>=!]+)([\d.]+)', constraint)
        if not op_match:
            return False
        op, ver = op_match.groups()
        inst_tuple = parse_version(installed)
        vuln_tuple = parse_version(ver)
        if op == "<=": return inst_tuple <= vuln_tuple
        if op == "<":  return inst_tuple < vuln_tuple
        if op == ">=": return inst_tuple >= vuln_tuple
        if op == ">":  return inst_tuple > vuln_tuple
        if op == "==": return inst_tuple == vuln_tuple
    except Exception:
        pass
    return False


def query_osv_api(package: str, version: str) -> List[dict]:
    """Query OSV.dev API for known vulnerabilities."""
    try:
        payload = json.dumps({
            "version": version,
            "package": {"name": package, "ecosystem": "PyPI"}
        }).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("vulns", [])
    except Exception:
        return []


class DependencyScanner:
    """Agent E: Scans Python dependencies for known CVEs."""

    AGENT_NAME = "Agent E - Dependency Scanner"

    def __init__(self, use_api: bool = True):
        self.use_api = use_api

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        """Find and scan all requirements files in the project."""
        findings = []
        scanned_paths = set()

        for analysis in analyses:
            project_root = Path(analysis.filepath).parent
            # Search up to 3 levels up for requirements files
            for _ in range(3):
                req_files = (
                    list(project_root.glob("requirements*.txt")) +
                    list(project_root.glob("setup.py")) +
                    list(project_root.glob("Pipfile"))
                )
                for req_file in req_files:
                    if str(req_file) not in scanned_paths:
                        scanned_paths.add(str(req_file))
                        findings.extend(self._scan_requirements(req_file))
                project_root = project_root.parent

        if not scanned_paths:
            print(f"  [Agent E] No requirements files found.")
        else:
            print(f"  [Agent E] Scanned: {', '.join(scanned_paths)}")

        return findings

    def _scan_requirements(self, req_path: Path) -> List[Finding]:
        findings = []
        try:
            content = req_path.read_text(encoding="utf-8")
        except Exception:
            return findings

        packages = self._parse_requirements(content)

        for pkg_name, version, lineno in packages:
            pkg_lower = pkg_name.lower()

            # Try live API first
            vulns = []
            if self.use_api and version:
                vulns = query_osv_api(pkg_lower, version)
                for vuln in vulns[:2]:  # Cap at 2 per package
                    aliases = vuln.get("aliases", [vuln.get("id", "UNKNOWN")])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), aliases[0] if aliases else "UNKNOWN")
                    summary = vuln.get("summary", "Known vulnerability detected.")
                    severity = self._osv_severity(vuln)
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=f"Vulnerable Dependency: {pkg_name}",
                        description=f"{pkg_name}=={version} has a known vulnerability ({cve_id}): {summary}",
                        severity=severity,
                        filepath=str(req_path),
                        lineno=lineno,
                        code_snippet=f"{pkg_name}=={version}",
                        recommendation=f"Upgrade {pkg_name} to the latest patched version. Run: pip install --upgrade {pkg_name}",
                        cwe_id="CWE-1035"
                    ))

            # Offline fallback
            if not vulns and pkg_lower in OFFLINE_VULN_DB:
                for constraint, cve, severity, desc in OFFLINE_VULN_DB[pkg_lower]:
                    if not version or version_affected(version, constraint):
                        findings.append(Finding(
                            agent=self.AGENT_NAME,
                            title=f"Vulnerable Dependency: {pkg_name}",
                            description=f"{pkg_name}{'==' + version if version else ''} may be affected by {cve}: {desc}",
                            severity=severity,
                            filepath=str(req_path),
                            lineno=lineno,
                            code_snippet=f"{pkg_name}{'==' + version if version else ''}",
                            recommendation=f"Upgrade {pkg_name} to the latest patched version. Run: pip install --upgrade {pkg_name}",
                            cwe_id="CWE-1035"
                        ))

            # Flag unpinned dependencies
            if not version:
                findings.append(Finding(
                    agent=self.AGENT_NAME,
                    title=f"Unpinned Dependency: {pkg_name}",
                    description=f"{pkg_name} has no version pinned. Unpinned dependencies can introduce breaking changes or vulnerabilities automatically.",
                    severity=Severity.LOW,
                    filepath=str(req_path),
                    lineno=lineno,
                    code_snippet=pkg_name,
                    recommendation=f"Pin to a specific version: {pkg_name}==<version>. Use 'pip freeze' to get current versions.",
                    cwe_id="CWE-1104"
                ))

        return findings

    def _parse_requirements(self, content: str) -> List[tuple]:
        """Parse requirements.txt into (name, version, lineno) tuples."""
        packages = []
        for lineno, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle pkg==version, pkg>=version, pkg~=version
            match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*([><=!~]+)\s*([\d\.]+)', line)
            if match:
                packages.append((match.group(1), match.group(3), lineno))
            else:
                # Just a package name, no version
                name_match = re.match(r'^([A-Za-z0-9_\-\.]+)', line)
                if name_match:
                    packages.append((name_match.group(1), None, lineno))
        return packages

    def _osv_severity(self, vuln: dict) -> Severity:
        """Map OSV severity to our Severity enum."""
        try:
            score = vuln.get("database_specific", {}).get("severity", "")
            cvss = vuln.get("severity", [{}])[0].get("score", "") if vuln.get("severity") else ""
            combined = (score + cvss).upper()
            if "CRITICAL" in combined: return Severity.CRITICAL
            if "HIGH" in combined:     return Severity.HIGH
            if "MEDIUM" in combined:   return Severity.MEDIUM
        except Exception:
            pass
        return Severity.MEDIUM
