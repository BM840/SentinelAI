"""
SentinelAI - Shared Data Models
"""
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    agent: str
    title: str
    description: str
    severity: Severity
    filepath: str
    lineno: Optional[int]
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    cwe_id: Optional[str] = None  # CWE reference

    def to_dict(self) -> dict:
        return {
            "agent": self.agent,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "filepath": self.filepath,
            "lineno": self.lineno,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id
        }
