from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class AuthorizationContext:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)

@dataclass(frozen=True)
class EndpointCase:
    method: str
    url: str
    parameters: list[str] = field(default_factory=list)
    security_required: bool | None = None
    operation_id: str | None = None
    tags: list[str] = field(default_factory=list)

@dataclass
class APIAnalysis:
    findings: list[dict[str, Any]] = field(default_factory=list)
    authorization_matrix: list[dict[str, Any]] = field(default_factory=list)
    negative_cases: list[dict[str, Any]] = field(default_factory=list)
    protocol_findings: list[dict[str, Any]] = field(default_factory=list)
