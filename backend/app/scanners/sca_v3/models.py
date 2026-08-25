from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ReachabilityEvidence:
    package: str
    ecosystem: str
    status: str  # direct, transitive, unreachable, unknown
    evidence: list[str] = field(default_factory=list)
    confidence: str = "low"

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class SupplyChainAssessment:
    package: str
    ecosystem: str
    indicators: list[dict[str, Any]] = field(default_factory=list)
    risk: str = "info"

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class SCAReachabilityResult:
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] = field(default_factory=dict)
    reachability: list[dict[str, Any]] = field(default_factory=list)
    supply_chain: list[dict[str, Any]] = field(default_factory=list)
    intelligence: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
