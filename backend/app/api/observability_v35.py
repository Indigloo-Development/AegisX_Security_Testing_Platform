from __future__ import annotations

import os
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from app.observability_v35 import publish_security_event, new_trace_context, trace_attributes, ROUTER, WebhookSink

router = APIRouter(prefix="/api/observability-v35", tags=["observability-v35"])


class SIEMEventRequest(BaseModel):
    event_type: str = Field(min_length=1, max_length=120)
    organization_id: str | None = None
    severity: str | None = None
    resource: str | None = None
    details: dict = Field(default_factory=dict)


class TraceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    parent_span_id: str | None = None
    attributes: dict = Field(default_factory=dict)


class WebhookConfig(BaseModel):
    url: str | None = None
    timeout_seconds: float = Field(default=5.0, ge=1.0, le=30.0)


@router.get("/capabilities")
def capabilities():
    return {
        "otel_context": True,
        "trace_correlation": True,
        "siem_router": True,
        "log_sink": True,
        "webhook_sink": True,
        "grafana_dashboard": True,
        "local_metrics": True,
        "external_metrics_required": False,
    }


@router.post("/events")
def create_security_event(payload: SIEMEventRequest, request: Request):
    return publish_security_event(
        payload.event_type,
        request_id=request.headers.get("X-Request-ID"),
        organization_id=payload.organization_id,
        severity=payload.severity,
        resource=payload.resource,
        details=payload.details,
    )


@router.post("/trace")
def create_trace(payload: TraceRequest):
    context = new_trace_context(payload.parent_span_id)
    return trace_attributes(payload.name, context, payload.attributes)


@router.get("/sinks")
def sink_status():
    return {
        "sinks": [
            {"name": "log", "enabled": True},
            {"name": "webhook", "enabled": bool(os.getenv("AEGISX_SECURITY_WEBHOOK_URL"))},
        ]
    }


@router.post("/sinks/webhook/test")
def test_webhook(payload: WebhookConfig):
    sink = WebhookSink(url=payload.url, timeout=payload.timeout_seconds)
    sample = publish_security_event("observability.webhook_test", details={"source": "aegisx"})
    # Test only the explicitly supplied sink; do not persist the URL.
    return sink.send(sample)
