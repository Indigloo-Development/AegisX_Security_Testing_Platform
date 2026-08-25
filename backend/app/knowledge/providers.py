from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable
from .models import Advisory

@dataclass
class ProviderResult:
    provider: str
    advisories: list[Advisory]
    ok: bool = True
    error: str | None = None

class AdvisoryProvider:
    name = 'base'
    def search(self, *, advisory_id: str | None = None, package: str | None = None, ecosystem: str | None = None) -> ProviderResult:
        raise NotImplementedError

class OfflineKnowledgeProvider(AdvisoryProvider):
    name = 'offline-knowledge'
    def __init__(self, advisories: Iterable[Advisory]) -> None:
        self._advisories = list(advisories)
    def search(self, *, advisory_id: str | None = None, package: str | None = None, ecosystem: str | None = None) -> ProviderResult:
        rows=[]
        for a in self._advisories:
            if advisory_id and a.advisory_id.lower() != advisory_id.lower():
                continue
            if package:
                matches=[x for x in a.affected if str(x.get('package','')).lower()==package.lower()]
                if not matches:
                    continue
                if ecosystem and not any(str(x.get('ecosystem','')).lower()==ecosystem.lower() for x in matches):
                    continue
            rows.append(a)
        return ProviderResult(self.name, rows)

# Provider adapters are intentionally network-neutral. Deployments can subclass
# AdvisoryProvider for NVD/OSV/KEV/vendor feeds without changing the knowledge API.
class ProviderRegistry:
    def __init__(self, providers: Iterable[AdvisoryProvider]):
        self.providers=list(providers)
    def names(self)->list[str]:
        return [p.name for p in self.providers]
    def search(self, **kwargs)->list[ProviderResult]:
        return [p.search(**kwargs) for p in self.providers]
