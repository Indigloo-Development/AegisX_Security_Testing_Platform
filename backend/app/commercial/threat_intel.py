from __future__ import annotations
from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class IntelRecord:
    identifier: str
    ecosystem: str
    severity: str
    summary: str
    fixed_version: str | None = None
    cwe: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

class ThreatIntelProvider:
    """Provider abstraction. Production deployments can implement NVD/OSV/KEV/EPSS adapters."""
    name = "offline-catalog"
    def lookup(self, ecosystem: str, name: str, version: str) -> list[IntelRecord]:
        return []

class OfflineIntelProvider(ThreatIntelProvider):
    name = "offline-catalog"
    _records = {
        ("pypi", "requests", "2.19.0"): IntelRecord("CVE-2018-18074", "pypi", "high", "Credential leakage risk through redirect handling in affected versions.", "2.20.0", ("CWE-200",)),
        ("npm", "lodash", "4.17.15"): IntelRecord("CVE-2019-10744", "npm", "high", "Prototype pollution vulnerability in affected Lodash versions.", "4.17.20", ("CWE-1321",)),
    }
    def lookup(self, ecosystem: str, name: str, version: str) -> list[IntelRecord]:
        record = self._records.get((ecosystem.lower(), name.lower(), version))
        return [record] if record else []

def enrich(component: dict[str, Any], provider: ThreatIntelProvider | None = None) -> list[dict[str, Any]]:
    provider = provider or OfflineIntelProvider()
    records = provider.lookup(component.get("ecosystem", ""), component.get("name", ""), component.get("version", ""))
    return [{"identifier": r.identifier, "severity": r.severity, "summary": r.summary, "fixed_version": r.fixed_version, "cwe": list(r.cwe), "references": list(r.references), "provider": provider.name} for r in records]
