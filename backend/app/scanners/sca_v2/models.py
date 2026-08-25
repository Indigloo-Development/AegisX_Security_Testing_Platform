from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ThreatIntelRecord:
    advisory_id: str
    package: str
    ecosystem: str
    severity: str
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    cwe: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    source: str = "offline"
    published: str | None = None
    modified: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class LicenseAssessment:
    package: str
    ecosystem: str
    declared: str | None
    classification: str
    reason: str

@dataclass
class SBOMDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)

@dataclass
class SCAIntelligenceResult:
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] = field(default_factory=dict)
    intelligence: list[dict[str, Any]] = field(default_factory=list)
    license_assessments: list[dict[str, Any]] = field(default_factory=list)
    supply_chain_indicators: list[dict[str, Any]] = field(default_factory=list)
    sbom_diff: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
