from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class RuleDefinition:
    key: str
    title: str
    category: str
    severity: str
    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    description: str = ""
    remediation: str = ""
    confidence: str = "confirmed"
    tags: tuple[str, ...] = ()

@dataclass
class PageContext:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str = ""
    final_url: str | None = None
    request_method: str = "GET"

@dataclass
class AdvancedAnalysis:
    findings: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
