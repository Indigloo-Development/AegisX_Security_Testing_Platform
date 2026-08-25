from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Dict, List, Optional

from app.commercial.authorization_v13 import Principal, AccessObservation, build_matrix, compare_observations, analyze_workflow

router = APIRouter(prefix="/api/authorization-v13", tags=["Authorization & Business Logic v13"])


class PrincipalModel(BaseModel):
    name: str
    role: str
    tenant: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)


class MatrixRequest(BaseModel):
    principals: List[PrincipalModel]
    endpoints: List[Dict]


class ObservationModel(BaseModel):
    principal: str
    role: str
    tenant: Optional[str] = None
    endpoint: str
    method: str = "GET"
    object_id: Optional[str] = None
    status: Optional[int] = None
    content_length: Optional[int] = None
    authorization_marker: Optional[str] = None


class CompareRequest(BaseModel):
    observations: List[ObservationModel]


class WorkflowRequest(BaseModel):
    states: List[Dict]


@router.post("/matrix")
def authorization_matrix(req: MatrixRequest):
    return build_matrix([Principal(**p.model_dump()) for p in req.principals], req.endpoints)


@router.post("/compare")
def authorization_compare(req: CompareRequest):
    findings = compare_observations([AccessObservation(**o.model_dump()) for o in req.observations])
    return {"count": len(findings), "findings": [f.__dict__ for f in findings]}


@router.post("/workflow")
def workflow(req: WorkflowRequest):
    return analyze_workflow(req.states)
