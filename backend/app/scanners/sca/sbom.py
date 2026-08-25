from __future__ import annotations
from datetime import datetime, timezone
from .models import Dependency


def generate_cyclonedx(dependencies: list[Dependency], project_name: str='AegisX Project') -> dict:
    components=[]
    for d in dependencies:
        c={'type':'library','bom-ref':f'{d.ecosystem}:{d.name}:{d.version}','name':d.name,'version':d.version,'purl':f'pkg:{d.ecosystem.lower()}/{d.name}@{d.version}'}
        if d.license: c['licenses']=[{'license':{'id':d.license}}]
        components.append(c)
    return {
      'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
      'metadata':{'timestamp':datetime.now(timezone.utc).isoformat(),'component':{'type':'application','name':project_name}},
      'components':components,
    }
