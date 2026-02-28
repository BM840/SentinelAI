#!/usr/bin/env python3
"""
SentinelAI - Multi-Agent AI Security Auditor for Python Web Applications
Usage:
    python main.py <target_path> [--no-llm] [--output-dir <dir>] [--ci-mode] [--diff]
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import AgentOrchestrator


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI - AI-powered security auditor for Python web apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py sample_app/                        # Full audit
  python main.py sample_app/ --no-llm              # Skip LLM (faster)
  python main.py sample_app/ --output-dir ./reports
  python main.py sample_app/ --ci-mode             # CI/CD: exit 1 if CRITICAL found
  python main.py sample_app/ --diff HEAD~1          # Scan only files changed since last commit
        """
    )
    parser.add_argument("target", help="Path to Python file or directory to audit")
    parser.add_argument("--no-llm", action="store_true",
                        help="Disable LLM-based analysis (Agent B runs in heuristic mode)")
    parser.add_argument("--output-dir", default="output",
                        help="Directory to save reports (default: ./output)")
    parser.add_argument("--ci-mode", action="store_true",
                        help="CI mode: exit code 1 if any CRITICAL findings, 2 if HIGH. "
                             "Compatible with GitHub Actions / GitLab CI.")
    parser.add_argument("--diff", metavar="GIT_REF",
                        help="Differential scan: only scan files changed since GIT_REF "
                             "(e.g. --diff HEAD~1 or --diff main)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                        default="critical",
                        help="In --ci-mode, minimum severity that triggers exit code 1 "
                             "(default: critical)")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[Error] Target not found: {args.target}")
        sys.exit(1)

    # ── Differential scan: get changed files since GIT_REF ────────────────
    scan_target = args.target
    if args.diff:
        changed = _get_changed_files(args.target, args.diff)
        if not changed:
            print(f"[SentinelAI] No Python files changed since {args.diff}. Nothing to scan.")
            sys.exit(0)
        print(f"[SentinelAI] Differential scan: {len(changed)} changed file(s) since {args.diff}")
        for f in changed:
            print(f"  {f}")
        # If only one changed file, scan it directly; else scan the directory
        # but orchestrator will filter by changed files list
        if len(changed) == 1:
            scan_target = changed[0]
        # For multiple files, pass them via environment variable (orchestrator checks it)
        else:
            os.environ["SENTINELAI_DIFF_FILES"] = ":".join(changed)

    os.makedirs(args.output_dir, exist_ok=True)

    if args.ci_mode:
        print(f"[SentinelAI] CI Mode enabled — will exit 1 if {args.fail_on.upper()} findings detected")

    orchestrator = AgentOrchestrator(
        target_path=scan_target,
        use_llm=not args.no_llm,
        output_dir=args.output_dir
    )

    result = orchestrator.run()

    if result:
        json_path = os.path.join(args.output_dir, "sentinel_report.json")
        md_path   = os.path.join(args.output_dir, "sentinel_report.md")
        orchestrator.save_json(json_path)
        orchestrator.save_report(md_path)
        print(f"\n[OK] Reports saved to: {args.output_dir}/")

        # ── CI Mode exit codes ─────────────────────────────────────────
        if args.ci_mode:
            summary = result.get("summary", {})
            sev_map  = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            sev_break = summary.get("severity_breakdown", {})
            threshold = args.fail_on.upper()
            threshold_idx = sev_map[args.fail_on]

            # Check if any findings at or above threshold exist
            triggered = False
            for sev, idx in [("CRITICAL", 0), ("HIGH", 1), ("MEDIUM", 2), ("LOW", 3)]:
                if idx <= threshold_idx and sev_break.get(sev, 0) > 0:
                    triggered = True
                    break

            if triggered:
                print(f"\n[CI] SCAN FAILED — {threshold} or higher findings detected.")
                print(f"[CI] Critical: {sev_break.get('CRITICAL',0)}  "
                      f"High: {sev_break.get('HIGH',0)}  "
                      f"Medium: {sev_break.get('MEDIUM',0)}  "
                      f"Low: {sev_break.get('LOW',0)}")
                print(f"[CI] Risk Score: {summary.get('risk_score', 0)}")
                print("[CI] Fix critical issues before merging. See report for details.")
                sys.exit(1)
            else:
                print(f"\n[CI] SCAN PASSED — No {threshold} or higher findings.")
                sys.exit(0)
    else:
        print("\n[!] No findings or no files analyzed.")
        if args.ci_mode:
            sys.exit(0)  # No findings = pass in CI


def _get_changed_files(base_path: str, git_ref: str) -> list:
    """Get list of Python files changed since git_ref."""
    import subprocess
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", git_ref, "HEAD", "--", "*.py"],
            cwd=base_path if os.path.isdir(base_path) else os.path.dirname(base_path),
            capture_output=True, text=True, timeout=10
        )
        files = [
            os.path.join(base_path, f.strip())
            for f in result.stdout.strip().splitlines()
            if f.strip().endswith(".py")
        ]
        return [f for f in files if os.path.exists(f)]
    except Exception as e:
        print(f"[Warning] Could not get diff from git: {e}")
        return []


if __name__ == "__main__":
    main()
