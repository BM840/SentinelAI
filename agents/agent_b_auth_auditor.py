"""
SentinelAI - Agent B: Authentication Logic Auditor (LLM-based)
Uses Ollama (local) or Anthropic API for semantic auth vulnerability detection.
Falls back to heuristic analysis if LLM is unavailable or fails.
"""
import re
import json
import ast as _ast
from typing import List, Optional
from core.models import Finding, Severity
from core.ingestion import FileAnalysis

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# ── Ollama config ──────────────────────────────────────────────────────────
OLLAMA_MODEL   = "phi3"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 90


def _try_ollama(prompt: str) -> str:
    import urllib.request
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 800, "num_ctx": 3072}
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
        return json.loads(resp.read()).get("response", "")


def _ollama_available() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434", timeout=2)
        return True
    except Exception:
        return False


# ── Plain-text format for phi3 (much more reliable than JSON) ─────────────
def _parse_plain_findings(raw: str, func_map: dict, filepath: str,
                           functions: list) -> List[Finding]:
    """
    Parse phi3 plain-text output in format:
      ISSUE[n]: function_name | SEVERITY | Title
      DESC[n]: description
      FIX[n]: recommendation
      CWE[n]: CWE-XXX
    """
    findings = []
    raw = raw.strip()

    # Find all ISSUE blocks
    issue_pattern = re.finditer(
        r'ISSUE\[(\d+)\]:\s*([^\n]+)\n'   # ISSUE[n]: func | SEV | Title
        r'(?:DESC\[(?:\d+)\]:\s*([^\n]+)\n?)?'
        r'(?:FIX\[(?:\d+)\]:\s*([^\n]+)\n?)?'
        r'(?:CWE\[(?:\d+)\]:\s*([^\n]+))?',
        raw, re.MULTILINE
    )

    for m in issue_pattern:
        idx       = m.group(1)
        meta      = m.group(2) or ""
        desc      = (m.group(3) or "").strip()
        fix       = (m.group(4) or "").strip()
        cwe       = (m.group(5) or "").strip()

        # Parse "func_name | SEVERITY | Title"
        parts = [p.strip() for p in meta.split("|")]
        if len(parts) < 3:
            continue

        func_name = parts[0].strip()
        sev_raw   = parts[1].strip().upper()
        title     = parts[2].strip()

        # Validate severity
        if sev_raw not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_raw = "MEDIUM"

        # Find the matching function object
        func_obj = func_map.get(func_name)
        if not func_obj and functions:
            # Try partial match
            for name, fobj in func_map.items():
                if func_name.lower() in name.lower() or name.lower() in func_name.lower():
                    func_obj = fobj
                    break
        if not func_obj:
            func_obj = functions[0]

        if not title or len(title) < 3:
            continue

        findings.append(Finding(
            agent="Agent B - Auth Logic Auditor (LLM)",
            title=title,
            description=desc or f"Authentication vulnerability detected in {func_name}",
            severity=Severity(sev_raw),
            filepath=filepath,
            lineno=func_obj.lineno,
            code_snippet=func_obj.source[:300] + ("..." if len(func_obj.source) > 300 else ""),
            recommendation=fix or "Review and fix the authentication logic.",
            cwe_id=cwe if cwe.startswith("CWE-") else None,
        ))

    return findings


def _build_batch_prompt(functions: list) -> tuple:
    """Build prompt and func_map for a batch of functions."""
    func_map = {}
    funcs_text = ""
    for i, func in enumerate(functions[:8]):
        func_map[func.name] = func
        funcs_text += f"\n[Function {i+1}: {func.name}, line {func.lineno}]\n{func.source[:350]}\n"

    prompt = (
        "You are a Python security expert. Find authentication and authorization "
        "vulnerabilities in these functions.\n\n"
        "For each vulnerability found, output EXACTLY this format:\n"
        "ISSUE[n]: function_name | SEVERITY | Short title\n"
        "DESC[n]: One sentence describing the vulnerability\n"
        "FIX[n]: One sentence on how to fix it\n"
        "CWE[n]: CWE-XXX\n\n"
        "SEVERITY must be one of: CRITICAL HIGH MEDIUM LOW\n"
        "n starts at 0 and increments for each issue.\n"
        "If no vulnerabilities found, write: NONE\n\n"
        "Functions to analyze:\n"
        f"{funcs_text}\n"
        "Vulnerabilities found:"
    )
    return prompt, func_map


class AuthenticationLogicAuditor:
    """
    Agent B: LLM-powered semantic analysis of authentication functions.
    Priority: Ollama (local GPU) → Anthropic API → Heuristic fallback
    """

    AGENT_NAME = "Agent B - Auth Logic Auditor (LLM)"

    def __init__(self, use_llm: bool = True):
        self.backend = "heuristic"
        self.client  = None

        if not use_llm:
            print("[Agent B] Running in heuristic-only mode.")
            return

        if _ollama_available():
            self.backend = "ollama"
            print(f"[Agent B] Using local Ollama ({OLLAMA_MODEL}) on GPU.")
            return

        if ANTHROPIC_AVAILABLE:
            try:
                self.client  = anthropic.Anthropic()
                self.backend = "anthropic"
                print("[Agent B] Using Anthropic Claude API.")
                return
            except Exception:
                pass

        print("[Agent B] No LLM available — running in heuristic mode.")

    @property
    def use_llm(self):
        return self.backend in ("anthropic", "ollama")

    # ── Main entry point ───────────────────────────────────────────────────
    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        findings = []
        for analysis in analyses:
            auth_fns = [f for f in analysis.functions if f.is_auth_related or f.is_route]
            if not auth_fns:
                continue
            if self.use_llm:
                findings.extend(self._analyze_batch(auth_fns, analysis.filepath))
            else:
                for func in auth_fns:
                    findings.extend(self._analyze_heuristic(func, analysis.filepath))
        return findings

    # ── LLM batch analysis ─────────────────────────────────────────────────
    def _analyze_batch(self, functions: list, filepath: str) -> List[Finding]:
        prompt, func_map = _build_batch_prompt(functions)

        try:
            raw = ""
            if self.backend == "ollama":
                raw = _try_ollama(prompt).strip()
            elif self.backend == "anthropic":
                resp = self.client.messages.create(
                    model="claude-opus-4-6",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )
                raw = resp.content[0].text.strip()

            # If response is empty or just "NONE", return nothing
            if not raw or raw.upper().startswith("NONE"):
                return []

            # Try plain-text format first (works well with phi3)
            findings = _parse_plain_findings(raw, func_map, filepath, functions)

            # If plain-text parsing found nothing, try JSON fallback
            if not findings:
                findings = self._try_json_parse(raw, func_map, filepath, functions)

            # If still nothing and we expected findings, use heuristic
            if not findings:
                print(f"[Agent B] Could not parse LLM response — using heuristic fallback")
                for func in functions:
                    findings.extend(self._analyze_heuristic(func, filepath))

            return findings

        except Exception as e:
            print(f"[Agent B] LLM batch failed: {e} — using heuristic fallback")
            result = []
            for func in functions:
                result.extend(self._analyze_heuristic(func, filepath))
            return result

    def _try_json_parse(self, raw: str, func_map: dict,
                         filepath: str, functions: list) -> List[Finding]:
        """Attempt to extract findings from JSON if plain-text parsing found nothing."""
        findings = []
        try:
            cleaned = re.sub(r"```json|```python|```", "", raw).strip()
            # Fix common phi3 JSON issues
            cleaned = re.sub(r",\s*}", "}", cleaned)
            cleaned = re.sub(r",\s*]", "]", cleaned)

            start = cleaned.find("[")
            end   = cleaned.rfind("]") + 1
            if start == -1 or end == 0:
                return []

            issues = json.loads(cleaned[start:end])
            for issue in issues:
                func_name = issue.get("function", "")
                func_obj  = func_map.get(func_name) or functions[0]
                sev = issue.get("severity", "MEDIUM").upper()
                if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    sev = "MEDIUM"
                findings.append(Finding(
                    agent=self.AGENT_NAME,
                    title=issue.get("title", "Authentication Issue"),
                    description=issue.get("description", ""),
                    severity=Severity(sev),
                    filepath=filepath,
                    lineno=func_obj.lineno,
                    code_snippet=func_obj.source[:300],
                    recommendation=issue.get("recommendation", ""),
                    cwe_id=issue.get("cwe_id"),
                ))
        except Exception:
            pass
        return findings

    # ── Heuristic fallback ─────────────────────────────────────────────────
    def _analyze_heuristic(self, func, filepath: str) -> List[Finding]:
        findings = []
        source = func.source

        if re.search(r'or\s+True\b', source):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Login Bypass - Always-True Condition",
                description="A condition using 'or True' always evaluates to True, bypassing authentication.",
                severity=Severity.CRITICAL,
                filepath=filepath, lineno=func.lineno,
                code_snippet=source[:300],
                recommendation="Remove the 'or True' condition and implement proper validation.",
                cwe_id="CWE-287"
            ))

        if re.search(r'==\s*["\']admin["\']', source) and re.search(r'return\s+True', source):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Privilege Escalation - Role Check Bypass",
                description="Admin role check may allow privilege escalation.",
                severity=Severity.HIGH,
                filepath=filepath, lineno=func.lineno,
                code_snippet=source[:300],
                recommendation="Verify role checks cannot be bypassed through logic flaws.",
                cwe_id="CWE-269"
            ))

        if re.search(r'@app\.route', source) and not re.search(
                r'@login_required|session\[|current_user|token|jwt|auth', source):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Unauthenticated Route Handler",
                description="This route has no visible authentication check.",
                severity=Severity.HIGH,
                filepath=filepath, lineno=func.lineno,
                code_snippet=source[:300],
                recommendation="Add authentication check using @login_required or verify session/token.",
                cwe_id="CWE-306"
            ))

        if re.search(r'password.*==|==.*password', source, re.IGNORECASE) and \
           not re.search(r'bcrypt|hash|pbkdf|argon|scrypt', source, re.IGNORECASE):
            findings.append(Finding(
                agent=self.AGENT_NAME + " [Heuristic]",
                title="Plaintext Password Comparison",
                description="Password appears to be compared in plaintext without hashing.",
                severity=Severity.CRITICAL,
                filepath=filepath, lineno=func.lineno,
                code_snippet=source[:300],
                recommendation="Use bcrypt.checkpw() to compare passwords. Never compare plaintext.",
                cwe_id="CWE-256"
            ))

        return findings
