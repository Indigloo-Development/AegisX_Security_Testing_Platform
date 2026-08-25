from __future__ import annotations
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, HttpUrl
from app.api.deps import get_local_operator
from app.models import User
from app.scanners.protocols import GraphQLValidator, SOAPValidator, GRPCValidator, WebDeepValidator

router = APIRouter(prefix="/api/protocol-validation", tags=["protocol-validation"])
_gql = GraphQLValidator(); _soap = SOAPValidator(); _grpc = GRPCValidator(); _web = WebDeepValidator()

class GraphQLRequest(BaseModel):
    schema_data: dict = Field(default_factory=dict, alias="schema")

class SOAPRequest(BaseModel):
    xml: str = Field(min_length=1, max_length=5_000_000)
    metadata: dict = Field(default_factory=dict)

class GRPCRequest(BaseModel):
    proto: str = Field(min_length=1, max_length=5_000_000)
    metadata: dict = Field(default_factory=dict)

class WebRequest(BaseModel):
    target_url: HttpUrl
    status: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=5_000_000)
    parameters: list[dict] = Field(default_factory=list, max_length=500)

@router.post("/graphql")
def validate_graphql(req: GraphQLRequest, user: User = Depends(get_local_operator)):
    return {"issues": [i.__dict__ for i in _gql.analyze(req.schema_data)]}

@router.post("/soap")
def validate_soap(req: SOAPRequest, user: User = Depends(get_local_operator)):
    return {"issues": [i.__dict__ for i in _soap.analyze(req.xml, req.metadata)]}

@router.post("/grpc")
def validate_grpc(req: GRPCRequest, user: User = Depends(get_local_operator)):
    return {"issues": [i.__dict__ for i in _grpc.analyze(req.proto, req.metadata)]}

@router.post("/web")
def validate_web(req: WebRequest, user: User = Depends(get_local_operator)):
    return {"issues": [i.__dict__ for i in _web.analyze(url=str(req.target_url), status=req.status, headers=req.headers, body=req.body, parameters=req.parameters)]}
