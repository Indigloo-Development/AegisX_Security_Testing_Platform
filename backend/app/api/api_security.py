from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models import User
from sqlalchemy.orm import Session
from app.scanners.api.scanner import APIScanner

router=APIRouter(prefix='/api/api-security',tags=['api-security'])
_engine=APIScanner()

class APIDiscoveryRequest(BaseModel):
    target_url: HttpUrl
    profile: str='standard'

@router.post('/discover')
def discover(body: APIDiscoveryRequest, db: Session=Depends(get_db), user: User=Depends(get_local_operator)):
    try:
        result=_engine.run(str(body.target_url),body.profile)
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    payload={'target_url':str(body.target_url),'profile':body.profile,'inventory':result.inventory,'findings':result.findings}
    try:
        from app.api.console_v42 import _persist_completed_analysis
        scan=_persist_completed_analysis(db,user,'API Endpoint Discovery',str(body.target_url),'api',payload)
        payload['scan_id']=scan.id
    except Exception as exc:
        # Preserve the discovery response even if persistence fails; operational logs expose the failure.
        payload['persistence_warning']=str(exc)
    return payload

from pydantic import BaseModel, Field
from app.scanners.api.deep.engine import APIDeepEngine

class OpenAPIDeepRequest(BaseModel):
    document: dict = Field(default_factory=dict)
    identities: list[str] = Field(default_factory=list, max_length=20)

class GraphQLDeepRequest(BaseModel):
    graphql_schema: dict = Field(default_factory=dict, alias="schema")

class SOAPDeepRequest(BaseModel):
    xml: str = Field(min_length=1, max_length=5_000_000)

class GRPCDeepRequest(BaseModel):
    proto: str = Field(min_length=1, max_length=5_000_000)
    reflection_enabled: bool = False

@router.post("/api-security/deep/openapi")
def deep_openapi(req: OpenAPIDeepRequest):
    return APIDeepEngine().analyze_openapi(req.document, req.identities)

@router.post("/api-security/deep/graphql")
def deep_graphql(req: GraphQLDeepRequest):
    return APIDeepEngine().analyze_graphql(req.graphql_schema)

@router.post("/api-security/deep/soap")
def deep_soap(req: SOAPDeepRequest):
    return APIDeepEngine().analyze_soap(req.xml)

@router.post("/api-security/deep/grpc")
def deep_grpc(req: GRPCDeepRequest):
    return APIDeepEngine().analyze_grpc(req.proto, req.reflection_enabled)
