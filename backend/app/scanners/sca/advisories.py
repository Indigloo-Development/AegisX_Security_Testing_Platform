from __future__ import annotations
from .models import Advisory

# Small deterministic seed catalog for offline tests. Production deployments should
# periodically import authoritative advisory feeds (e.g. OSV/NVD/vendor advisories).
ADVISORIES=[
    Advisory('AX-TEST-NPM-001','lodash','npm','<4.17.21','high','Prototype pollution in older lodash releases',['CWE-1321'],['4.17.21']),
    Advisory('AX-TEST-PY-001','requests','PyPI','<2.32.0','medium','Requests version below supported security baseline',[],['2.32.0']),
]

def _tuple(v:str):
    import re
    m=re.findall(r'\d+',v or '')
    return tuple(int(x) for x in (m[:4] or ['0']))

def affects(advisory: Advisory, version: str) -> bool:
    if version in ('unknown',''): return False
    v=_tuple(version)
    spec=advisory.affected_versions.strip()
    if spec.startswith('<'):
        return v < _tuple(spec[1:])
    if spec.startswith('<='):
        return v <= _tuple(spec[2:])
    return False

def find_advisories(name:str, ecosystem:str, version:str):
    return [a for a in ADVISORIES if a.package.lower()==name.lower() and a.ecosystem.lower()==ecosystem.lower() and affects(a, version)]
