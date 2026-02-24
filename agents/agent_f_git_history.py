"""
SentinelAI - Agent F: Git History Secrets Scanner
Scans git commit history for secrets that were added and later deleted.
Deleted secrets in git history are still accessible to anyone who clones the repo.
"""
import re
import subprocess
from pathlib import Path
from typing import List, Optional
from core.models import Finding, Severity
from core.ingestion import FileAnalysis


# Secret patterns to search for in git history
SECRET_PATTERNS = [
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
     "Password in Git History", "CWE-312"),
    (r'sk-[a-zA-Z0-9]{20,}',
     "OpenAI API Key in Git History", "CWE-312"),
    (r'sk-ant-[a-zA-Z0-9\-_]{20,}',
     "Anthropic API Key in Git History", "CWE-312"),
    (r'AKIA[A-Z0-9]{16}',
     "AWS Access Key in Git History", "CWE-312"),
    (r'ghp_[a-zA-Z0-9]{36}',
     "GitHub Personal Access Token in Git History", "CWE-312"),
    (r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][^"\']{8,}["\']',
     "API Key in Git History", "CWE-312"),
    (r'(?i)(secret_key|secret)\s*=\s*["\'][^"\']{8,}["\']',
     "Secret Key in Git History", "CWE-312"),
    (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
     "Private Key in Git History", "CWE-321"),
    (r'(?i)(token|auth_token)\s*=\s*["\'][^"\']{8,}["\']',
     "Auth Token in Git History", "CWE-312"),
    (r'mongodb(\+srv)?://[^:]+:[^@]+@',
     "MongoDB Connection String with Credentials in Git History", "CWE-312"),
    (r'postgres://[^:]+:[^@]+@',
     "PostgreSQL Connection String with Credentials in Git History", "CWE-312"),
]

# False positive filters
EXCLUDE_PATTERNS = [
    "example", "placeholder", "your_key", "changeme", "xxxxxxx",
    "12345", "test", "dummy", "fake", "sample", "abcdef",
]


def is_git_repo(path: Path) -> bool:
    """Check if path is inside a git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(path),
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def get_git_root(path: Path) -> Optional[Path]:
    """Get the root directory of the git repository."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(path),
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return Path(result.stdout.strip())
    except Exception:
        pass
    return None


def get_commit_history(git_root: Path, max_commits: int = 100) -> List[dict]:
    """Get list of commits from git log."""
    try:
        result = subprocess.run(
            ["git", "log", f"--max-count={max_commits}",
             "--pretty=format:%H|%s|%an|%ad", "--date=short"],
            cwd=str(git_root),
            capture_output=True, text=True, timeout=15
        )
        commits = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) >= 2:
                commits.append({
                    "hash": parts[0],
                    "message": parts[1] if len(parts) > 1 else "",
                    "author": parts[2] if len(parts) > 2 else "",
                    "date": parts[3] if len(parts) > 3 else "",
                })
        return commits
    except Exception:
        return []


def get_commit_diff(git_root: Path, commit_hash: str) -> str:
    """Get the diff for a specific commit."""
    try:
        result = subprocess.run(
            ["git", "show", "--diff-filter=A", "-p", commit_hash],
            cwd=str(git_root),
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except Exception:
        return ""


class GitHistoryScanner:
    """Agent F: Scans git history for secrets that were committed and deleted."""

    AGENT_NAME = "Agent F - Git History Scanner"

    def __init__(self, max_commits: int = 100):
        self.max_commits = max_commits

    def analyze(self, analyses: List[FileAnalysis]) -> List[Finding]:
        if not analyses:
            return []

        # Find git root from first analyzed file
        first_path = Path(analyses[0].filepath).parent
        
        if not is_git_repo(first_path):
            print(f"  [Agent F] No git repository found. Skipping history scan.")
            return []

        git_root = get_git_root(first_path)
        if not git_root:
            return []

        print(f"  [Agent F] Scanning git history at: {git_root}")
        return self._scan_history(git_root)

    def _scan_history(self, git_root: Path) -> List[Finding]:
        findings = []
        seen_secrets = set()

        commits = get_commit_history(git_root, self.max_commits)
        if not commits:
            print(f"  [Agent F] No commits found or git not available.")
            return []

        print(f"  [Agent F] Scanning {len(commits)} commits...")

        for commit in commits:
            diff = get_commit_diff(git_root, commit["hash"])
            if not diff:
                continue

            # Only look at added lines (prefixed with +)
            added_lines = [
                (i, line[1:])  # strip the leading +
                for i, line in enumerate(diff.splitlines(), 1)
                if line.startswith("+") and not line.startswith("+++")
            ]

            for lineno, line in added_lines:
                for pattern, title, cwe in SECRET_PATTERNS:
                    match = re.search(pattern, line)
                    if match:
                        matched_text = match.group(0)

                        # Skip false positives
                        if any(fp in matched_text.lower() for fp in EXCLUDE_PATTERNS):
                            continue

                        # Deduplicate by secret content
                        dedup_key = (title, matched_text[:30])
                        if dedup_key in seen_secrets:
                            continue
                        seen_secrets.add(dedup_key)

                        findings.append(Finding(
                            agent=self.AGENT_NAME,
                            title=title,
                            description=(
                                f"A potential secret was found in commit {commit['hash'][:8]} "
                                f"({commit['date']}) by {commit['author']}. "
                                f"Even if deleted from current code, this secret remains "
                                f"accessible in git history to anyone with repo access."
                            ),
                            severity=Severity.HIGH,
                            filepath=str(git_root / ".git"),
                            lineno=None,
                            code_snippet=f"Commit: {commit['hash'][:8]} | {commit['message'][:60]}\n{line.strip()[:120]}",
                            recommendation=(
                                "1. Rotate/revoke the exposed secret immediately.\n"
                                "2. Use 'git filter-repo' or BFG Repo Cleaner to purge from history.\n"
                                "3. Force-push the cleaned history.\n"
                                "4. Use environment variables for all secrets going forward."
                            ),
                            cwe_id=cwe
                        ))

        return findings
