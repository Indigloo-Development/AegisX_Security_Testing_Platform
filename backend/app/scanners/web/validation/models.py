from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class ValidationFinding:
    key: str
    title: str
    severity: str
    confidence: str
    category: str
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    description: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.key,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }

@dataclass(frozen=True)
class WorkflowStep:
    name: str
    method: str
    path: str
    expected_status: tuple[int, ...] = ()
    requires_auth: bool = False
    state_change: bool = False
    expected_role: str | None = None

@dataclass
class WorkflowAnalysis:
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    normalized_steps: list[dict[str, Any]] = field(default_factory=list)
