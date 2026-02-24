"""
SentinelAI - Agent B: Authentication Logic Auditor (Ollama-based)
Uses local Ollama LLM for semantic reasoning.
Falls back to heuristic analysis if Ollama fails.
"""

import re
import json
import requests
from typing import List, Optional
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


SYSTEM_PROMPT = """You are a senior application security engineer specializing in authentication vulnerabilities.

Analyze the given Python function for:
- Login bypass logic
- Privilege escalation
- Missing authentication checks
- Broken access control

Respond ONLY with a JSON array:
[
  {
    "title": "...",
    "description": "...",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "recommendation": "...",
    "cwe_id": "CWE-xxx"
  }
]

If no issues found, return [].
"""


class AuthenticationLogicAuditor:

    AGENT_NAME = "Agent B - Auth Logic Auditor (Ollama)"

    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm
        if self.use_llm:
            print("[Agent B] Using Ollama local model.")
        else:
            print("[Agent B] Running in heuristic-only mode.")

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []

        for analysis in analyses:
            auth_functions = [
                f for f in analysis.functions
                if f.is_auth_related or f.is_route
            ]

            for func in auth_functions:
                if self.use_llm:
                    findings.extend(self._analyze_with_ollama(func, analysis.filepath))
                else:
                    findings.extend(self._analyze_heuristic(func, analysis.filepath))

        return findings

    # ---------------- LLM (Ollama) ----------------

    def _analyze_with_ollama(self, func, filepath: str) -> List[Finding]:
        findings = []

        prompt = f"""{SYSTEM_PROMPT}

Function:
{func.source}
"""

        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": "llama3",   # or deepseek-coder
                    "prompt": prompt,
                    "stream": False
                },
                timeout=60
            )

            raw = response.json().get("response", "").strip()
            raw = re.sub(r"```json|```", "", raw).strip()

            issues = json.loads(raw)

            for issue in issues:
                findings.append(Finding(
                    agent=self.AGENT_NAME,
                    title=issue.get("title", "Authentication Issue"),
                    description=issue.get("description", ""),
                    severity=Severity(issue.get("severity", "MEDIUM")),
                    filepath=filepath,
                    lineno=func.lineno,
                    code_snippet=func.source[:300],
                    recommendation=issue.get("recommendation", ""),
                    cwe_id=issue.get("cwe_id")
                ))

        except Exception as e:
            print(f"[Agent B] Ollama failed for {func.name}: {e}")
            findings.extend(self._analyze_heuristic(func, filepath))

        return findings

    # ---------------- Heuristic Fallback ----------------

    def _analyze_heuristic(self, func, filepath: str) -> List[Finding]:
        findings = []
        source = func.source

        if re.search(r'or\s+True\b', source):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Login Bypass - Always-True Condition",
                description=f"Function '{func.name}' contains 'or True' which bypasses authentication.",
                severity=Severity.CRITICAL,
                filepath=filepath,
                lineno=func.lineno,
                code_snippet=self._extract_line(source, "or True"),
                recommendation="Remove always-true conditions.",
                cwe_id="CWE-287"
            ))

        if func.is_route and not any(
            kw in source.lower() for kw in
            ["session", "token", "auth", "login_required", "jwt"]
        ):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Unauthenticated Route Handler",
                description=f"Route '{func.name}' does not verify authentication.",
                severity=Severity.MEDIUM,
                filepath=filepath,
                lineno=func.lineno,
                code_snippet=func.source[:200],
                recommendation="Add authentication checks.",
                cwe_id="CWE-306"
            ))

        return findings

    def _extract_line(self, source: str, keyword: str) -> Optional[str]:
        for line in source.splitlines():
            if keyword in line:
                return line.strip()
        return None