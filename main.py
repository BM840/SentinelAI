#!/usr/bin/env python3
"""
SentinelAI - Multi-Agent AI Security Auditor for Python Web Applications
Usage:
    python main.py <target_path> [--no-llm] [--output-dir <dir>]
"""
import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import AgentOrchestrator


def main():
    parser = argparse.ArgumentParser(
        description="SentinelAI - AI-powered security auditor for Python web apps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py sample_app/              # Audit a directory
  python main.py sample_app/app.py        # Audit a single file
  python main.py sample_app/ --no-llm    # Skip LLM analysis (faster)
  python main.py sample_app/ --output-dir ./reports
        """
    )
    parser.add_argument("target", help="Path to Python file or directory to audit")
    parser.add_argument("--no-llm", action="store_true",
                        help="Disable LLM-based analysis (Agent B runs in heuristic mode)")
    parser.add_argument("--output-dir", default="output",
                        help="Directory to save reports (default: ./output)")

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"[Error] Target not found: {args.target}")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    orchestrator = AgentOrchestrator(
        target_path=args.target,
        use_llm=not args.no_llm
    )

    result = orchestrator.run()

    if result:
        json_path = os.path.join(args.output_dir, "sentinel_report.json")
        md_path = os.path.join(args.output_dir, "sentinel_report.md")
        orchestrator.save_json(json_path)
        orchestrator.save_report(md_path)
        print(f"\n✅ Reports saved to: {args.output_dir}/")
    else:
        print("\n⚠️  No findings or no files analyzed.")


if __name__ == "__main__":
    main()
