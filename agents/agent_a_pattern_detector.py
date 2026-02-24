"""
SentinelAI - Agent A: Pattern Vulnerability Detector
Uses AST and regex patterns to detect common code-level vulnerabilities.
"""
import ast
import re
from typing import List
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Patterns for hardcoded secrets detection
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd|secret|api_key|apikey|token|auth_key|private_key)\s*=\s*["\'][^"\']{4,}["\']',
     "Hardcoded Secret", "CWE-798"),
    (r'(?i)(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[A-Z0-9]{16})',
     "Exposed API Key", "CWE-798"),
]

# SQL concatenation patterns
SQL_CONCAT_PATTERNS = [
    r'(?i)(execute|cursor\.execute)\s*\(\s*[f"\'](SELECT|INSERT|UPDATE|DELETE)',
    r'(?i)"SELECT.*"\s*\+\s*\w',
    r"(?i)'SELECT.*'\s*\+\s*\w",
    r'(?i)f"SELECT.*\{',
    r"(?i)f'SELECT.*\{",
    r'(?i)(execute|cursor\.execute)\s*\(.*\+\s*\w',
]


class PatternVulnerabilityDetector:
    """Agent A: Detects pattern-based vulnerabilities via AST and regex."""

    AGENT_NAME = "Agent A - Pattern Detector"

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []
        for analysis in analyses:
            findings.extend(self._scan_file(analysis))
        return findings

    def _scan_file(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        findings.extend(self._detect_hardcoded_secrets(analysis))
        findings.extend(self._detect_eval_usage(analysis))
        findings.extend(self._detect_sql_injection(analysis))
        findings.extend(self._detect_debug_flags(analysis))
        findings.extend(self._detect_plaintext_password(analysis))
        return findings

    def _detect_hardcoded_secrets(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern, title, cwe in SECRET_PATTERNS:
                if re.search(pattern, line):
                    # Avoid flagging obvious test/example strings
                    if any(skip in line.lower() for skip in ["example", "placeholder", "your_key_here", "changeme"]):
                        continue
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title=title,
                        description=f"Potential hardcoded credential or secret detected on line {lineno}.",
                        severity=Severity.CRITICAL,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation="Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager) instead of hardcoding secrets.",
                        cwe_id=cwe
                    ))
        return findings

    def _detect_eval_usage(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        for node in ast.walk(analysis.ast_tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "eval":
                    line_src = analysis.source_code.splitlines()[node.lineno - 1].strip()
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title="Use of eval() Detected",
                        description=f"eval() on line {node.lineno} can execute arbitrary code if user input is passed.",
                        severity=Severity.CRITICAL,
                        filepath=analysis.filepath,
                        lineno=node.lineno,
                        code_snippet=line_src,
                        recommendation="Avoid eval() entirely. Use safe alternatives like ast.literal_eval() for data parsing, or redesign the logic.",
                        cwe_id="CWE-95"
                    ))
        return findings

    def _detect_sql_injection(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()
        for lineno, line in enumerate(lines, start=1):
            for pattern in SQL_CONCAT_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title="SQL Injection Risk - String Concatenation in Query",
                        description=f"Line {lineno} appears to build a SQL query via string concatenation or f-string, which is vulnerable to SQL injection.",
                        severity=Severity.HIGH,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation="Use parameterized queries or an ORM (e.g., SQLAlchemy). Never concatenate user input directly into SQL.",
                        cwe_id="CWE-89"
                    ))
                    break  # Only one finding per line
        return findings

    def _detect_debug_flags(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()
        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.search(r'(?i)(DEBUG\s*=\s*True|app\.config\[.DEBUG.\]\s*=\s*True)', stripped):
                findings.append(Finding(
                    agent=self.AGENT_NAME,
                    title="Debug Mode Enabled",
                    description=f"Debug mode is enabled on line {lineno}. In production, this exposes stack traces, internal state, and may enable the interactive debugger.",
                    severity=Severity.MEDIUM,
                    filepath=analysis.filepath,
                    lineno=lineno,
                    code_snippet=stripped,
                    recommendation="Disable debug mode in production. Use environment-based configuration (e.g., DEBUG = os.getenv('DEBUG', 'False') == 'True').",
                    cwe_id="CWE-215"
                ))
        return findings

    def _detect_plaintext_password(self, analysis: FileAnalysis) -> List[Finding]:
        findings = []
        lines = analysis.source_code.splitlines()
        for lineno, line in enumerate(lines, start=1):
            # Look for plaintext password comparison patterns
            if re.search(r'(?i)(password|passwd|pwd)\s*==\s*\w', line):
                # Exclude hashing-related lines
                if not any(h in line.lower() for h in ["hash", "bcrypt", "sha", "md5", "pbkdf"]):
                    findings.append(Finding(
                        agent=self.AGENT_NAME,
                        title="Plaintext Password Comparison",
                        description=f"Line {lineno} compares a password in plaintext. Passwords should be hashed before storage and comparison.",
                        severity=Severity.HIGH,
                        filepath=analysis.filepath,
                        lineno=lineno,
                        code_snippet=line.strip(),
                        recommendation="Use bcrypt, argon2, or PBKDF2 for password hashing. Never store or compare plaintext passwords.",
                        cwe_id="CWE-256"
                    ))
        return findings
