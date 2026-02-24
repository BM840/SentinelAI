"""
SentinelAI - Agent D: Risk Scoring Agent
Aggregates findings, deduplicates, assigns risk scores, and generates a summary.
"""
from typing import List, Dict, Tuple
from collections import defaultdict
from core.models import Finding, Severity


SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
}

RISK_THRESHOLDS = [
    (0, "SAFE - No significant vulnerabilities detected."),
    (5, "LOW RISK - Minor issues present, review recommended."),
    (15, "MEDIUM RISK - Notable vulnerabilities found, remediation advised."),
    (30, "HIGH RISK - Significant vulnerabilities detected, immediate action required."),
    (float("inf"), "CRITICAL RISK - Severe security flaws present. Do NOT deploy without remediation."),
]


class RiskScoringAgent:
    """Agent D: Consolidates, deduplicates, and scores all findings."""

    AGENT_NAME = "Agent D - Risk Scoring"

    def analyze(self, all_findings: List[Finding]) -> Tuple[List[Finding], Dict]:
        deduplicated = self._deduplicate(all_findings)
        risk_score, risk_level = self._calculate_risk(deduplicated)
        summary = self._build_summary(deduplicated, risk_score, risk_level)
        return deduplicated, summary

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on title + filepath + lineno."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.title.lower(), f.filepath, f.lineno)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _calculate_risk(self, findings: List[Finding]) -> Tuple[int, str]:
        total_score = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

        risk_level = RISK_THRESHOLDS[-1][1]
        for threshold, label in RISK_THRESHOLDS:
            if total_score <= threshold:
                risk_level = label
                break

        return total_score, risk_level

    def _build_summary(self, findings: List[Finding], risk_score: int, risk_level: str) -> Dict:
        by_severity = defaultdict(list)
        by_agent = defaultdict(list)
        by_file = defaultdict(list)

        for f in findings:
            by_severity[f.severity.value].append(f)
            by_agent[f.agent].append(f)
            by_file[f.filepath].append(f)

        return {
            "total_findings": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "severity_breakdown": {
                sev: len(items) for sev, items in by_severity.items()
            },
            "findings_by_agent": {
                agent: len(items) for agent, items in by_agent.items()
            },
            "files_scanned": list(by_file.keys()),
            "most_vulnerable_files": [
                {"file": fp, "count": len(items)}
                for fp, items in sorted(by_file.items(), key=lambda x: len(x[1]), reverse=True)[:3]
            ]
        }
