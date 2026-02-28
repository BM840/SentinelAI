"""
SentinelAI - Shared Data Models
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """How certain we are about a finding."""
    HIGH   = "HIGH"    # AST / deterministic detection
    MEDIUM = "MEDIUM"  # Pattern / regex match
    LOW    = "LOW"     # LLM inference / heuristic


@dataclass
class Finding:
    agent:          str
    title:          str
    description:    str
    severity:       Severity
    filepath:       str
    lineno:         Optional[int]
    code_snippet:   Optional[str]  = None
    recommendation: Optional[str]  = None
    cwe_id:         Optional[str]  = None
    fix_suggestion: Optional[dict] = None
    owasp_id:       Optional[str]  = None
    owasp_name:     Optional[str]  = None
    owasp_url:      Optional[str]  = None
    confidence:     Confidence     = Confidence.MEDIUM   # NEW
    llm_used:       bool           = False               # NEW — was LLM involved?
    llm_available:  bool           = True                # NEW — did LLM succeed?

    def to_dict(self) -> dict:
        return {
            "agent":          self.agent,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity.value,
            "filepath":       self.filepath,
            "lineno":         self.lineno,
            "code_snippet":   self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id":         self.cwe_id,
            "fix_suggestion": self.fix_suggestion,
            "owasp_id":       self.owasp_id,
            "owasp_name":     self.owasp_name,
            "owasp_url":      self.owasp_url,
            "confidence":     self.confidence.value,
            "llm_used":       self.llm_used,
            "llm_available":  self.llm_available,
        }
