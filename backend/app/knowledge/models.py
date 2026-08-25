from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    summary: str
    severity: str = 'unknown'
    cvss: float | None = None
    epss: float | None = None
    kev: bool = False
    cwe: tuple[str, ...] = ()
    capec: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    affected: tuple[dict[str, Any], ...] = ()
    fixed_versions: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    published: str | None = None
    modified: str | None = None
    source: str = 'offline'

    def as_dict(self) -> dict[str, Any]:
        return {
            'advisory_id': self.advisory_id, 'summary': self.summary,
            'severity': self.severity, 'cvss': self.cvss, 'epss': self.epss,
            'kev': self.kev, 'cwe': list(self.cwe), 'capec': list(self.capec),
            'owasp': list(self.owasp), 'mitre': list(self.mitre),
            'affected': [dict(x) for x in self.affected],
            'fixed_versions': list(self.fixed_versions), 'references': list(self.references),
            'published': self.published, 'modified': self.modified, 'source': self.source,
        }

@dataclass(frozen=True)
class Mapping:
    source_id: str
    relation: str
    target_id: str
    framework: str

    def as_dict(self) -> dict[str, str]:
        return {'source_id': self.source_id, 'relation': self.relation, 'target_id': self.target_id, 'framework': self.framework}

@dataclass
class KnowledgeQueryResult:
    advisories: list[dict[str, Any]] = field(default_factory=list)
    mappings: list[dict[str, Any]] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    cached: bool = True
    query: dict[str, Any] = field(default_factory=dict)
