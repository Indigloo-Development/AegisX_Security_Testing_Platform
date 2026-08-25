from __future__ import annotations
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.models import User
from app.knowledge.store import KB

router=APIRouter(prefix='/api/knowledge', tags=['vulnerability-knowledge'])

class KnowledgeImportRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=2000)

@router.get('/summary')
def summary(user: User = Depends(get_local_operator)):
    return KB.summary()

@router.get('/providers')
def providers(user: User = Depends(get_local_operator)):
    return {'providers': KB.provider_names(), 'network_enabled': False, 'note': 'Provider adapters are pluggable; this deployment uses deterministic offline knowledge.'}

@router.get('/search')
def search(advisory_id: str|None=None, package: str|None=None, ecosystem: str|None=None, severity: str|None=None, user: User = Depends(get_local_operator)):
    return KB.search(advisory_id=advisory_id, package=package, ecosystem=ecosystem, severity=severity).__dict__

@router.post('/import')
def import_records(body: KnowledgeImportRequest, user: User = Depends(get_local_operator)):
    return {'added': KB.import_advisories(body.records), 'summary': KB.summary()}

@router.get('/export')
def export(user: User = Depends(get_local_operator)):
    return KB.export()
