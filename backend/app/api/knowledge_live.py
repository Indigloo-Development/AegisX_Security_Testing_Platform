from __future__ import annotations
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.api.deps import get_local_operator
from app.models import User
from app.knowledge.live import NVDProvider, OSVProvider, KEVProvider
from app.knowledge.store import KB

router=APIRouter(prefix='/api/knowledge-live', tags=['live-threat-intelligence'])

class NVDRequest(BaseModel):
    advisory_id: str|None=None; keyword: str|None=None; force_refresh: bool=False
class OSVRequest(BaseModel):
    package: str=Field(min_length=1,max_length=256); ecosystem: str=Field(min_length=1,max_length=128); version: str|None=None; force_refresh: bool=False
class KEVRequest(BaseModel):
    advisory_id: str=Field(min_length=1,max_length=64); force_refresh: bool=False


def _ingest(rows):
    for a in rows: KB.import_advisories([a.as_dict()])

@router.get('/providers')
def providers(user:User=Depends(get_local_operator)): return {'providers':['nvd-2.0','osv','cisa-kev'],'live_enabled':True,'refresh_policy':'TTL cache; default 1h'}

@router.post('/nvd/search')
def nvd_search(body:NVDRequest,user:User=Depends(get_local_operator)):
    result=NVDProvider().search(body.advisory_id,body.keyword,body.force_refresh); _ingest(result.advisories)
    return {'provider':result.source,'ok':result.ok,'error':result.error,'cached':result.cached,'fetched_at':result.fetched_at,'count':len(result.advisories),'advisories':[a.as_dict() for a in result.advisories]}

@router.post('/osv/query')
def osv_query(body:OSVRequest,user:User=Depends(get_local_operator)):
    result=OSVProvider().search(body.package,body.ecosystem,body.version,body.force_refresh); _ingest(result.advisories)
    return {'provider':result.source,'ok':result.ok,'error':result.error,'cached':result.cached,'fetched_at':result.fetched_at,'count':len(result.advisories),'advisories':[a.as_dict() for a in result.advisories]}

@router.post('/kev/check')
def kev_check(body:KEVRequest,user:User=Depends(get_local_operator)):
    result=KEVProvider().search(body.advisory_id,body.force_refresh); _ingest(result.advisories)
    return {'provider':result.source,'ok':result.ok,'error':result.error,'cached':result.cached,'fetched_at':result.fetched_at,'count':len(result.advisories),'advisories':[a.as_dict() for a in result.advisories]}

@router.get('/graph/{advisory_id}')
def graph(advisory_id:str,user:User=Depends(get_local_operator)):
    result=KB.search(advisory_id=advisory_id)
    nodes=[]; edges=[]
    for a in result.advisories:
        root=a['advisory_id']; nodes.append({'id':root,'type':'advisory','label':root})
        for field in ('cwe','capec','owasp','mitre'):
            for target in a.get(field,[]):
                nid=f'{field}:{target}'; nodes.append({'id':nid,'type':field,'label':target}); edges.append({'source':root,'target':nid,'relation':'mapped_to'})
        for x in a.get('affected',[]):
            pkg=str(x.get('package','')); eco=str(x.get('ecosystem',''))
            if pkg:
                nid=f'package:{eco}:{pkg}'; nodes.append({'id':nid,'type':'package','label':pkg,'ecosystem':eco}); edges.append({'source':nid,'target':root,'relation':'affected_by'})
    # stable deduplication
    uniq_nodes={n['id']:n for n in nodes}; uniq_edges={f"{e['source']}|{e['target']}|{e['relation']}":e for e in edges}
    return {'nodes':list(uniq_nodes.values()),'edges':list(uniq_edges.values()),'advisories':result.advisories}
