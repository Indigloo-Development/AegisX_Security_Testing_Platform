from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models.models import User
from app.transport_v32 import TransportError, build_transport

router = APIRouter(prefix="/api/enterprise-v32", tags=["enterprise-v32"])


class TransportConfig(BaseModel):
    backend: str = Field(default="memory", pattern=r"^(memory|redis|rabbitmq|amqp)$")
    url: str | None = Field(default=None, max_length=2048)
    queue: str = Field(default="aegisx.scan", min_length=1, max_length=128)


class PublishRequest(TransportConfig):
    payload: dict = Field(default_factory=dict)


@router.post("/transport/health")
def transport_health(body: TransportConfig, user: User = Depends(get_local_operator)):
    if user.role.value != "admin":
        raise HTTPException(403, "admin role required")
    try:
        transport = build_transport(body.backend, body.url)
        return {"backend": body.backend, "status": "configured", "queue": transport.stats(body.queue)}
    except TransportError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/transport/publish")
def transport_publish(body: PublishRequest, user: User = Depends(get_local_operator)):
    if user.role.value not in {"admin", "analyst"}:
        raise HTTPException(403, "scan permission required")
    try:
        transport = build_transport(body.backend, body.url)
        message = {"organization_id": user.organization_id, "payload": body.payload}
        receipt = transport.publish(body.queue, message)
        return {"receipt": receipt, "queue": body.queue, "backend": body.backend}
    except TransportError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/transport/queue")
def transport_queue(backend: str = "memory", url: str | None = None, queue: str = "aegisx.scan", user: User = Depends(get_local_operator)):
    if user.role.value != "admin":
        raise HTTPException(403, "admin role required")
    try:
        transport = build_transport(backend, url)
        return transport.stats(queue)
    except TransportError as exc:
        raise HTTPException(400, str(exc)) from exc
