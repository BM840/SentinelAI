"""
SentinelAI - Agent Orchestrator
Coordinates all agents, manages execution flow, and collects results.
"""
import json
import time
from typing import List, Dict
from core.ingestion import CodeIngestionLayer
from core.models import Finding
from agents.agent_a_pattern_detector import PatternVulnerabilityDetector
from agents.agent_b_auth_auditor import AuthenticationLogicAuditor
from agents.agent_c_dataflow import DataFlowAnalyzer
from agents.agent_d_risk_scorer import RiskScoringAgent
from agents.agent_e_dependency_scanner import DependencyScanner
from agents.agent_f_git_history import GitHistoryScanner
from agents.agent_g_cors_headers import CORSAndHeadersAuditor
from agents.agent_h_cryptography import WeakCryptographyDetector
from agents.agent_i_autofix import AutoFixEngine
from core.owasp import annotate_findings


class AgentOrchestrator:
    """
    Coordinates all SentinelAI agents:
      1. Code Ingestion Layer
      2. Agent A - Pattern Vulnerability Detector
      3. Agent B - Authentication Logic Auditor (LLM)
      4. Agent C - Data Flow Analyzer
      5. Agent D - Risk Scoring Agent
    """

    def __init__(self, target_path: str, use_llm: bool = True, output_dir: str = "output"):
        self.target_path = target_path
        self.use_llm = use_llm
        self.output_dir = output_dir
        self.all_findings: List[Finding] = []
        self.summary: Dict = {}

    def run(self) -> Dict:
        print("\n" + "="*60)
        print("  SentinelAI - Multi-Agent Security Auditor")
        print("="*60)
        start_time = time.time()

        # Step 1: Ingestion
        print("\n[Orchestrator] Phase 1: Code Ingestion")
        ingestion = CodeIngestionLayer(self.target_path)
        analyses = ingestion.ingest()

        if not analyses:
            print("[Orchestrator] No Python files found to analyze.")
            return {}

        # Step 2: Agent A
        print("\n[Orchestrator] Phase 2: Running Agent A - Pattern Detector")
        agent_a = PatternVulnerabilityDetector()
        findings_a = agent_a.analyze(analyses)
        print(f"  -> Agent A found {len(findings_a)} issue(s).")
        self.all_findings.extend(findings_a)

        # Step 3: Agent B
        print("\n[Orchestrator] Phase 3: Running Agent B - Auth Logic Auditor")
        agent_b = AuthenticationLogicAuditor(use_llm=self.use_llm)
        findings_b = agent_b.analyze(analyses)
        print(f"  -> Agent B found {len(findings_b)} issue(s).")
        self.all_findings.extend(findings_b)

        # Step 4: Agent C
        print("\n[Orchestrator] Phase 4: Running Agent C - Data Flow Analyzer")
        agent_c = DataFlowAnalyzer()
        findings_c = agent_c.analyze(analyses)
        print(f"  -> Agent C found {len(findings_c)} issue(s).")
        self.all_findings.extend(findings_c)

        # Step 5: Agent E - Dependency Scanner
        print("\n[Orchestrator] Phase 5: Running Agent E - Dependency Scanner")
        agent_e = DependencyScanner(use_api=False)
        findings_e = agent_e.analyze(analyses)
        print(f"  -> Agent E found {len(findings_e)} issue(s).")
        self.all_findings.extend(findings_e)

        # Step 6: Agent F - Git History Scanner
        print("\n[Orchestrator] Phase 6: Running Agent F - Git History Scanner")
        agent_f = GitHistoryScanner()
        findings_f = agent_f.analyze(analyses)
        print(f"  -> Agent F found {len(findings_f)} issue(s).")
        self.all_findings.extend(findings_f)

        # Step 7: Agent G - CORS and Headers Auditor
        print("\n[Orchestrator] Phase 7: Running Agent G - CORS & Headers Auditor")
        agent_g = CORSAndHeadersAuditor()
        findings_g = agent_g.analyze(analyses)
        print(f"  -> Agent G found {len(findings_g)} issue(s).")
        self.all_findings.extend(findings_g)

        # Step 8: Agent H - Cryptography Auditor
        print("\n[Orchestrator] Phase 8: Running Agent H - Cryptography Auditor")
        agent_h = WeakCryptographyDetector()
        findings_h = agent_h.analyze(analyses)
        print(f"  -> Agent H found {len(findings_h)} issue(s).")
        self.all_findings.extend(findings_h)


        # Step 9: Agent D - Risk Scoring
        print("\n[Orchestrator] Phase 9: Running Agent D - Risk Scoring")
        agent_d = RiskScoringAgent()
        final_findings, summary = agent_d.analyze(self.all_findings)
        self.all_findings = final_findings
        self.summary = summary

        # Annotate all findings with OWASP Top 10 categories
        annotate_findings(self.all_findings)
        owasp_hits = sum(1 for f in self.all_findings if getattr(f, "owasp_id", ""))
        print(f"\n[Orchestrator] OWASP mapping: {owasp_hits}/{len(self.all_findings)} findings tagged")

        # Step 10: Agent I - Auto-Fix Engine
        print("\n[Orchestrator] Phase 10: Running Agent I - Auto-Fix Engine")
        agent_i = AutoFixEngine(use_llm=self.use_llm)
        fix_result = agent_i.generate_fixes(self.all_findings, analyses)
        stats = fix_result["stats"]
        print(f"  -> Agent I generated {stats['total_fixes_generated']} fix(es) "
              f"({stats['ollama_fixes']} Ollama, {stats['rule_fixes']} rule-based)")

        # Save fix report and patched files
        if self.output_dir:
            agent_i.save_fix_report(fix_result, self.output_dir)
            patched = agent_i.save_patched_files(fix_result["patched_files"], self.output_dir)
            self.summary["fixes_generated"]   = stats["total_fixes_generated"]
            self.summary["files_patched"]     = stats["files_patched"]
            self.summary["patched_file_paths"]= patched

        elapsed = round(time.time() - start_time, 2)
        self.summary["scan_duration_seconds"] = elapsed
        self.summary["target_path"] = self.target_path

        self._print_summary()
        return self._build_output()

    def _print_summary(self):
        s = self.summary
        print("\n" + "="*60)
        print("  SCAN COMPLETE - RISK SUMMARY")
        print("="*60)
        print(f"  Target:        {s.get('target_path')}")
        print(f"  Duration:      {s.get('scan_duration_seconds')}s")
        print(f"  Total Issues:  {s.get('total_findings')}")
        print(f"  Risk Score:    {s.get('risk_score')}")
        print(f"  Risk Level:    {s.get('risk_level')}")
        print()
        print("  Severity Breakdown:")
        for sev, count in s.get("severity_breakdown", {}).items():
            bar = "#" * min(count * 3, 30)
            print(f"    {sev:<10} {count:>3}  {bar}")
        print()
        print("  Top Findings:")
        sorted_findings = sorted(
            self.all_findings,
            key=lambda f: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f.severity.value),
            reverse=True
        )
        for f in sorted_findings[:5]:
            owasp = getattr(f, "owasp_id", "")
            owasp_str = f"  [{owasp}]" if owasp else ""
            print(f"    [{f.severity.value}] {f.title} - Line {f.lineno}{owasp_str}")
        print()
        # OWASP breakdown
        from collections import Counter
        owasp_counts = Counter(
            f"{getattr(f,'owasp_id','')} — {getattr(f,'owasp_name','')}"
            for f in self.all_findings
            if getattr(f, "owasp_id", "")
        )
        if owasp_counts:
            print("  OWASP Top 10 Breakdown:")
            for category, count in sorted(owasp_counts.items()):
                print(f"    {category}: {count} finding(s)")
        print("="*60 + "\n")

    def _build_output(self) -> Dict:
        return {
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.all_findings]
        }

    def save_json(self, output_path: str):
        output = self._build_output()
        with open(output_path, "w") as fp:
            json.dump(output, fp, indent=2)
        print(f"[Orchestrator] JSON report saved to: {output_path}")

    def save_report(self, output_path: str):
        """Generate a human-readable markdown security report."""
        s = self.summary
        lines = [
            "# SentinelAI Security Audit Report",
            "",
            "## Executive Summary",
            "",
            f"- **Target:** `{s.get('target_path')}`",
            f"- **Total Findings:** {s.get('total_findings')}",
            f"- **Risk Score:** {s.get('risk_score')}",
            f"- **Risk Level:** {s.get('risk_level')}",
            f"- **Scan Duration:** {s.get('scan_duration_seconds')}s",
            "",
            "## Severity Breakdown",
            "",
        ]
        for sev, count in s.get("severity_breakdown", {}).items():
            lines.append(f"- **{sev}:** {count}")

        lines += ["", "## Findings", ""]

        sorted_findings = sorted(
            self.all_findings,
            key=lambda f: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(f.severity.value),
            reverse=True
        )

        for i, f in enumerate(sorted_findings, 1):
            lines += [
                f"### {i}. [{f.severity.value}] {f.title}",
                "",
                f"- **Agent:** {f.agent}",
                f"- **File:** `{f.filepath}`",
                f"- **Line:** {f.lineno}",
                f"- **CWE:** {f.cwe_id or 'N/A'}",
                "",
                f"**Description:** {f.description}",
                "",
            ]
            if f.code_snippet:
                lines += [
                    "**Code Snippet:**",
                    "```python",
                    f.code_snippet,
                    "```",
                    "",
                ]
            if f.recommendation:
                lines += [
                    f"**Recommendation:** {f.recommendation}",
                    "",
                ]
            lines.append("---")
            lines.append("")

        with open(output_path, "w") as fp:
            fp.write("\n".join(lines))
        print(f"[Orchestrator] Markdown report saved to: {output_path}")
