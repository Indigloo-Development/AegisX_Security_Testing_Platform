from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_local_operator
from app.models import User
from app.scanners.sca.scanner import SCAScanner

router=APIRouter(prefix='/api/sca', tags=['sca'])
_engine=SCAScanner()

class SCARequest(BaseModel):
    source_path: str = Field(min_length=1, max_length=1000)
    profile: str='standard'

@router.post('/scan')
def scan(body:SCARequest, user:User=Depends(get_local_operator)):
    try:
        result=_engine.scan_path(body.source_path,body.profile)
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return {'source_path':body.source_path,'profile':body.profile,'manifests':result.manifests,'dependency_count':len(result.dependencies),'dependencies':[d.as_dict() for d in result.dependencies],'sbom':result.sbom,'findings':result.findings}
