from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_local_operator
from app.models import User
from app.scanners.api.fuzzing.engine import APIFuzzEngine, observation

router = APIRouter(prefix="/api/api-fuzz-v16", tags=["api-fuzzing-v16"])
_engine = APIFuzzEngine()


class OpenAPIFuzzRequest(BaseModel):
    document: dict = Field(default_factory=dict)
    max_cases: int = Field(default=120, ge=1, le=500)


class ObservationModel(BaseModel):
    identity: str = Field(min_length=1, max_length=100)
    status: int | None = Field(default=None, ge=100, le=599)
    content_type: str | None = Field(default=None, max_length=200)
    content_length: int | None = Field(default=None, ge=0)
    body: str | None = Field(default=None, max_length=2_000_000)
    markers: list[str] = Field(default_factory=list, max_length=50)


class DifferentialRequest(BaseModel):
    observations: list[ObservationModel] = Field(min_length=2, max_length=20)


class WorkflowRequest(BaseModel):
    steps: list[dict] = Field(min_length=1, max_length=100)


@router.post("/openapi/cases")
def openapi_cases(req: OpenAPIFuzzRequest, user: User = Depends(get_local_operator)):
    result = _engine.generate_openapi_cases(req.document, req.max_cases)
    return {
        "case_count": len(result.cases),
        "cases": [c.__dict__ for c in result.cases],
        "safe_execution": "bounded_non_destructive",
    }


@router.post("/differential")
def differential(req: DifferentialRequest, user: User = Depends(get_local_operator)):
    obs = [observation(x.identity, x.status, x.content_type, x.content_length, x.body, x.markers) for x in req.observations]
    return _engine.compare_observations(obs)


@router.post("/workflow")
def workflow(req: WorkflowRequest, user: User = Depends(get_local_operator)):
    return _engine.build_workflow(req.steps)
