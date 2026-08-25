from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.scaling_v33 import WorkerScalingPolicy, desired_replicas

router = APIRouter(prefix="/api/scaling-v33", tags=["scaling-v33"])


class ScaleRequest(BaseModel):
    queue_depth: int = Field(ge=0)
    current_replicas: int = Field(ge=1)


@router.post("/desired-replicas")
def desired(request: ScaleRequest):
    policy = WorkerScalingPolicy.from_env()
    replicas = desired_replicas(request.queue_depth, request.current_replicas, policy)
    return {"desired_replicas": replicas, "queue_depth": request.queue_depth, "policy": policy.__dict__}
