from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    direct: bool = True
    scope: str = "runtime"
    manifest: str = ""
    license: str | None = None
    source: str = ""
    reachable: bool | None = None

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class Advisory:
    advisory_id: str
    package: str
    ecosystem: str
    affected_versions: str
    severity: str
    title: str
    cwe: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)

@dataclass
class SCAResult:
    manifests: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    sbom: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
