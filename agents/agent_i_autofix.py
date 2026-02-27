"""
SentinelAI - Agent I: Auto-Fix Engine
Uses a simple numbered text format (not JSON) for Ollama responses,
then parses them reliably. Falls back to rule-based fixes instantly.
"""
import re
import os
import json
from pathlib import Path
from typing import List, Tuple
from core.models import Finding, Severity
from core.ingestion import FileAnalysis

OLLAMA_MODEL   = "phi3"
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 120

def _ollama_available() -> bool:
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:11434", timeout=2)
        return True
    except Exception:
        return False

def _ask_ollama(prompt: str) -> str:
    import urllib.request, json as _j
    payload = _j.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1200, "num_ctx": 3072}
    }).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
        return _j.loads(resp.read()).get("response", "")

# ── Rule-based fallback ────────────────────────────────────────────────────
RULE_FIXES = {
    "hardcoded secret":      ('os.environ.get("SECRET_KEY", "")',
                              'Move secret to an environment variable instead of hardcoding it.'),
    "exposed api key":       ('os.environ.get("API_KEY", "")',
                              'Never hardcode API keys. Read from environment variables.'),
    "debug mode":            ('app.run(debug=os.environ.get("FLASK_DEBUG","false")=="true")',
                              'Read debug flag from environment. Never hardcode debug=True.'),
    "eval()":                ('ast.literal_eval(user_input)  # import ast first',
                              'Replace eval() with ast.literal_eval() for safe evaluation.'),
    "sql injection":         ('cursor.execute("SELECT * FROM t WHERE id=?", (val,))',
                              'Use parameterized queries. Never build SQL with string formatting.'),
    "plaintext password":    ('bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())  # pip install bcrypt',
                              'Hash passwords with bcrypt. Never store or compare plaintext.'),
    "weak hash":             ('hashlib.sha256(data.encode()).hexdigest()',
                              'MD5/SHA1 are broken. Use SHA-256 for data, bcrypt for passwords.'),
    "insecure random":       ('secrets.token_hex(32)  # import secrets',
                              'Use the secrets module for security tokens, not random.'),
    "verify=false":          ('requests.get(url, verify=True)',
                              'Never disable SSL verification. Remove verify=False.'),
    "cors":                  ('CORS(app, origins=["https://yourdomain.com"])',
                              'Specify explicit trusted origins instead of wildcard *.'),
    "vulnerable dependency": ('# In requirements.txt — upgrade to latest secure version:\n# pip install --upgrade <package>',
                              'Upgrade this package to the latest version to patch the vulnerability.'),
    "unpinned dependency":   ('flask==3.0.3  # Pin to a specific secure version',
                              'Pin all dependencies to exact versions to prevent unexpected upgrades.'),
    "git history":           ('# Rotate this credential immediately.\n# Use: git filter-branch or BFG Repo-Cleaner to purge from history.',
                              'Rotate the exposed credential immediately and purge it from git history.'),
    "unauthenticated":       ('@login_required  # Add this decorator above the route\ndef your_route():',
                              'Add authentication check — use @login_required or verify session/token.'),
    "login bypass":          ('if not (username and password and check_password(user, password)):\n    return "Invalid credentials", 401',
                              'Remove always-true conditions. Verify both username and password properly.'),
    "privilege escalation":  ('if current_user.role != "admin":\n    return "Forbidden", 403',
                              'Fix role check logic — ensure it cannot be bypassed by any user.'),
    "unsanitized":           ('# Validate and sanitize all user input before use\nvalue = escape(request.form.get("input", ""))',
                              'Sanitize all user input. Never pass raw user data to dangerous functions.'),
}

def _rule_fix(finding: Finding) -> Tuple[str, str]:
    t = finding.title.lower()
    for kw, (fix, expl) in RULE_FIXES.items():
        if kw in t:
            return fix, expl
    return "# See recommendation above", finding.recommendation or ""

# ── Batch Ollama with plain text format (not JSON) ─────────────────────────
BATCH_SIZE = 8   # smaller batches = more reliable responses

def _batch_ollama_fix(findings: List[Finding], offset: int) -> dict:
    """
    Send a batch of findings to Ollama using plain numbered format.
    phi3 handles this much more reliably than JSON output.
    Returns dict: global_index -> {after, explanation}
    """
    lines = []
    for i, f in enumerate(findings):
        snippet = (f.code_snippet or "no snippet")[:150].replace("\n", " ")
        lines.append(f"[{i}] {f.title}: {snippet}")

    prompt = (
        "Fix each Python security vulnerability below.\n"
        "For each number, write exactly:\n"
        "FIX[number]: the fixed code on one line\n"
        "WHY[number]: one sentence explanation\n\n"
        "Example:\n"
        "FIX[0]: password = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())\n"
        "WHY[0]: Use bcrypt to hash passwords instead of storing plaintext.\n\n"
        "Vulnerabilities:\n" +
        "\n".join(lines) +
        "\n\nProvide FIX and WHY for each number:"
    )

    try:
        raw = _ask_ollama(prompt)
        results = {}

        for i in range(len(findings)):
            # Extract FIX[i]
            fix_match = re.search(rf'FIX\[{i}\]:\s*(.+?)(?=\nWHY|\nFIX|\Z)', raw, re.DOTALL)
            why_match = re.search(rf'WHY\[{i}\]:\s*(.+?)(?=\nFIX|\nWHY|\Z)', raw, re.DOTALL)

            if fix_match:
                fix_code = fix_match.group(1).strip()
                # Clean up markdown if phi3 added it
                fix_code = re.sub(r'```python|```', '', fix_code).strip()
                why_text = why_match.group(1).strip()[:200] if why_match else ""
                if fix_code:
                    results[offset + i] = {"after": fix_code, "explanation": why_text}

        return results

    except Exception as e:
        print(f"  [Agent I] Batch {offset//BATCH_SIZE + 1} failed: {e}")
        return {}


# ── File patcher ───────────────────────────────────────────────────────────
def _patch_source(source_code: str, fixes: List[dict]) -> Tuple[str, int]:
    lines   = source_code.splitlines(keepends=True)
    patched = list(lines)
    applied = 0
    for fix in fixes:
        lineno = fix.get("lineno")
        before = (fix.get("before") or "").strip()
        after  = (fix.get("after")  or "").strip()
        if not lineno or not before or not after or "\n" in after:
            continue
        idx = lineno - 1
        if 0 <= idx < len(patched):
            line = patched[idx]
            if before in line:
                new_line = line.replace(before, after, 1)
                if new_line != line:
                    patched[idx] = new_line
                    applied += 1
    return "".join(patched), applied


# ── Main Agent ─────────────────────────────────────────────────────────────
class AutoFixEngine:
    AGENT_NAME = "Agent I - Auto-Fix Engine"

    def __init__(self, use_llm: bool = True):
        self.use_ollama = use_llm and _ollama_available()
        if self.use_ollama:
            print(f"  [Agent I] Ollama ({OLLAMA_MODEL}) ready — batched fix mode")
        else:
            print(f"  [Agent I] Ollama unavailable — using instant rule-based fixes")

    def generate_fixes(self, findings: List[Finding], analyses: List[FileAnalysis]) -> dict:
        source_map = {a.filepath: a.source_code for a in analyses}

        # Deduplicate
        seen, unique = set(), []
        for f in findings:
            key = f.title.lower()[:60] if ("dependency" in f.title.lower() or
                  "git history" in f.title.lower()) else (f.title.lower()[:40], f.filepath, f.lineno)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        total = len(unique)

        # Split into: code findings (need LLM) vs simple findings (rule-based is enough)
        RULE_ONLY_KEYWORDS = ["dependency", "git history", "unpinned"]
        llm_findings  = [f for f in unique if not any(k in f.title.lower() for k in RULE_ONLY_KEYWORDS)]
        rule_findings = [f for f in unique if     any(k in f.title.lower() for k in RULE_ONLY_KEYWORDS)]

        print(f"  [Agent I] {total} unique findings: "
              f"{len(llm_findings)} need LLM fix, "
              f"{len(rule_findings)} use instant rule fix "
              f"(deduplicated from {len(findings)})")

        # Run Ollama only on code findings
        ollama_results = {}
        if self.use_ollama and llm_findings:
            chunks = [llm_findings[i:i+BATCH_SIZE] for i in range(0, len(llm_findings), BATCH_SIZE)]
            for idx, chunk in enumerate(chunks):
                print(f"  [Agent I] Ollama batch {idx+1}/{len(chunks)} ({len(chunk)} code findings)...", flush=True)
                batch = _batch_ollama_fix(chunk, idx * BATCH_SIZE)
                ollama_results.update(batch)
            success = len(ollama_results)
            print(f"  [Agent I] Ollama fixed {success}/{len(llm_findings)} code findings")

        # Rebuild unique list: llm_findings first (so indices match), then rule_findings
        unique = llm_findings + rule_findings

        # Build fix list
        fixes, ollama_count, rule_count = [], 0, 0

        for i, finding in enumerate(unique):
            before = (finding.code_snippet or "").strip()

            if i in ollama_results:
                data  = ollama_results[i]
                after = str(data.get("after", "")).strip()
                expl  = str(data.get("explanation", "")).strip()
                if after:
                    ollama_count += 1
                    fix_type = "ollama"
                else:
                    after, expl = _rule_fix(finding)
                    rule_count += 1
                    fix_type = "rule"
            else:
                after, expl = _rule_fix(finding)
                fix_type = "rule"
                rule_count += 1

            fix_obj = {
                "finding_title": finding.title,
                "severity":      finding.severity.value,
                "filepath":      finding.filepath or "",
                "lineno":        finding.lineno,
                "before":        before,
                "after":         after,
                "explanation":   expl,
                "type":          fix_type,
            }
            fixes.append(fix_obj)
            finding.fix_suggestion = {
                "before": before, "after": after,
                "explanation": expl, "type": fix_type,
            }

        # Patch files
        patched_files = {}
        for filepath, original in source_map.items():
            file_fixes = [f for f in fixes if f["filepath"] == filepath]
            if file_fixes:
                patched_src, n = _patch_source(original, file_fixes)
                if n > 0:
                    patched_files[filepath] = {
                        "source": patched_src, "lines_patched": n,
                        "fixes_applied": [f["finding_title"] for f in file_fixes
                                          if f.get("before") and "\n" not in (f.get("after") or "")
                                          and (f.get("before") or "") in original],
                    }

        stats = {
            "total_fixes_generated": len(fixes),
            "ollama_fixes":  ollama_count,
            "rule_fixes":    rule_count,
            "files_patched": len(patched_files),
        }
        return {"fixes": fixes, "patched_files": patched_files, "stats": stats}

    def save_patched_files(self, patched_files: dict, output_dir: str) -> List[str]:
        if not patched_files:
            return []
        patch_dir = os.path.join(output_dir, "patched")
        os.makedirs(patch_dir, exist_ok=True)
        saved = []
        for filepath, info in patched_files.items():
            filename = Path(filepath).name
            out_path = os.path.join(patch_dir, f"FIXED_{filename}")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(info["source"])
            print(f"  [Agent I] Patched file saved ({info['lines_patched']} line(s) fixed): {out_path}")
            for a in info.get("fixes_applied", [])[:3]:
                print(f"            - {a}")
            saved.append(out_path)
        return saved

    def save_fix_report(self, result: dict, output_dir: str) -> str:
        out_path = os.path.join(output_dir, "fix_suggestions.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"stats": result["stats"], "fixes": result["fixes"]}, f, indent=2)
        return out_path
