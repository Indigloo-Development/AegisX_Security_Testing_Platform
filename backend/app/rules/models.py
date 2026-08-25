from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

Detector = Callable[["ScanContext", "RuleDefinition"], Sequence["RuleFinding"]]

@dataclass(frozen=True)
class Evidence:
    type: str
    location: str
    snippet: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class RuleDefinition:
    key: str
    title: str
    family: str
    severity: str
    confidence: str
    description: str
    remediation: str
    protocols: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    detector: str = "generic"
    active: bool = True

@dataclass
class ScanContext:
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    content_type: str = ""
    parameters: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    protocol: str = "web"
    role: str | None = None

@dataclass(frozen=True)
class RuleFinding:
    rule_key: str
    title: str
    family: str
    severity: str
    confidence: str
    description: str
    remediation: str
    evidence: tuple[Evidence, ...] = ()
    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    location: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_key": self.rule_key,
            "title": self.title,
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "remediation": self.remediation,
            "location": self.location,
            "owasp": list(self.owasp),
            "cwe": list(self.cwe),
            "tags": list(self.tags),
            "evidence": [
                {"type": e.type, "location": e.location, "snippet": e.snippet, "metadata": dict(e.metadata)}
                for e in self.evidence
            ],
        }
