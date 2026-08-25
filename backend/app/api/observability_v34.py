from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.observability import event

router = APIRouter(prefix="/api/observability-v34", tags=["observability-v34"])

class SecurityEventRequest(BaseModel):
    event_type: str = Field(min_length=1, max_length=100)
    actor: str | None = None
    organization_id: str | None = None
    severity: str | None = None
    resource: str | None = None
    details: dict = Field(default_factory=dict)

@router.post("/events")
def create_event(payload: SecurityEventRequest, request: Request):
    request_id = request.headers.get("X-Request-ID")
    return event(payload.event_type, request_id=request_id, actor=payload.actor, organization_id=payload.organization_id, severity=payload.severity, resource=payload.resource, details=payload.details)

@router.get("/capabilities")
def capabilities():
    return {
        "local_metrics": True,
        "structured_events": True,
        "otel_ready": True,
        "trace_span_hooks": True,
        "dashboard_ready": True,
        "external_collector_required": False,
    }
