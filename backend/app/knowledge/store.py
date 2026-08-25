from __future__ import annotations
import threading
from typing import Any
from .catalog import ADVISORIES, MAPPINGS
from .models import Advisory, KnowledgeQueryResult, Mapping
from .providers import OfflineKnowledgeProvider, ProviderRegistry, AdvisoryProvider

class KnowledgeBase:
    def __init__(self, providers: list[AdvisoryProvider] | None = None):
        self._lock=threading.RLock()
        self._advisories={a.advisory_id:a for a in ADVISORIES}
        self._mappings=list(MAPPINGS)
        self._registry=ProviderRegistry(providers or [OfflineKnowledgeProvider(self._advisories.values())])
    def provider_names(self)->list[str]: return self._registry.names()
    def summary(self)->dict[str, Any]:
        with self._lock:
            severities={s:sum(1 for a in self._advisories.values() if a.severity==s) for s in ('critical','high','medium','low','unknown')}
            return {'advisories':len(self._advisories),'mappings':len(self._mappings),'providers':self.provider_names(),'severity_counts':severities}
    def search(self, *, advisory_id: str|None=None, package: str|None=None, ecosystem: str|None=None, severity: str|None=None)->KnowledgeQueryResult:
        results=[]
        for a in self._advisories.values():
            if advisory_id and a.advisory_id.lower()!=advisory_id.lower(): continue
            if severity and a.severity.lower()!=severity.lower(): continue
            if package and not any(str(x.get('package','')).lower()==package.lower() and (not ecosystem or str(x.get('ecosystem','')).lower()==ecosystem.lower()) for x in a.affected): continue
            results.append(a.as_dict())
        ids={x['advisory_id'] for x in results}
        maps=[m.as_dict() for m in self._mappings if m.source_id in ids or m.source_id in {c for x in results for c in x.get('cwe',[])+x.get('capec',[])} or m.target_id in {c for x in results for c in x.get('cwe',[])+x.get('capec',[])}]
        return KnowledgeQueryResult(results,maps,self.provider_names(),True,{'advisory_id':advisory_id,'package':package,'ecosystem':ecosystem,'severity':severity})
    def import_advisories(self, rows:list[dict[str,Any]])->int:
        added=0
        with self._lock:
            for row in rows:
                try:
                    aid=str(row['advisory_id'])
                    if aid in self._advisories: continue
                    affected=tuple(dict(x) for x in row.get('affected',[]))
                    a=Advisory(aid,str(row.get('summary','')),str(row.get('severity','unknown')),float(row['cvss']) if row.get('cvss') is not None else None,float(row['epss']) if row.get('epss') is not None else None,bool(row.get('kev',False)),tuple(map(str,row.get('cwe',[]))),tuple(map(str,row.get('capec',[]))),tuple(map(str,row.get('owasp',[]))),tuple(map(str,row.get('mitre',[]))),affected,tuple(map(str,row.get('fixed_versions',[]))),tuple(map(str,row.get('references',[]))),row.get('published'),row.get('modified'),str(row.get('source','imported')))
                    self._advisories[aid]=a; added+=1
                except (KeyError,TypeError,ValueError):
                    continue
        return added
    def export(self)->dict[str,Any]:
        return {'advisories':[a.as_dict() for a in self._advisories.values()], 'mappings':[m.as_dict() for m in self._mappings], 'providers':self.provider_names()}

KB=KnowledgeBase()
