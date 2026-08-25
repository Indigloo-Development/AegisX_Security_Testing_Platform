from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any

from app.observability import event

log = logging.getLogger("aegisx.observability.v35")


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: str | None = None


def new_trace_context(parent_span_id: str | None = None) -> TraceContext:
    return TraceContext(trace_id=uuid.uuid4().hex, span_id=uuid.uuid4().hex, parent_span_id=parent_span_id)


def trace_attributes(name: str, context: TraceContext, attributes: dict[str, Any] | None = None) -> dict[str, Any]:
    data = {
        "name": name,
        "trace_id": context.trace_id,
        "span_id": context.span_id,
        "parent_span_id": context.parent_span_id,
        "attributes": attributes or {},
    }
    log.debug("otel_span", extra={"event": data})
    return data


class EventSink:
    name = "base"

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError


class LogSink(EventSink):
    name = "log"

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        log.info("siem_event", extra={"event": payload})
        return {"accepted": True, "sink": self.name}


class WebhookSink(EventSink):
    name = "webhook"

    def __init__(self, url: str | None = None, timeout: float = 5.0) -> None:
        self.url = url or os.getenv("AEGISX_SECURITY_WEBHOOK_URL")
        self.timeout = timeout

    def send(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.url:
            return {"accepted": False, "sink": self.name, "reason": "webhook_not_configured"}
        # Import lazily so an observability-only deployment does not require a new HTTP client.
        import httpx
        response = httpx.post(self.url, json=payload, timeout=self.timeout)
        response.raise_for_status()
        return {"accepted": True, "sink": self.name, "status_code": response.status_code}


class SecurityEventRouter:
    def __init__(self, sinks: list[EventSink] | None = None) -> None:
        self.sinks = sinks or [LogSink()]

    def route(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for sink in self.sinks:
            try:
                results.append(sink.send(payload))
            except Exception as exc:  # noqa: BLE001
                log.exception("security_event_sink_failed", extra={"sink": sink.name})
                results.append({"accepted": False, "sink": sink.name, "error": str(exc)})
        return results


ROUTER = SecurityEventRouter()


def publish_security_event(event_type: str, *, request_id: str | None = None, organization_id: str | None = None,
                           severity: str | None = None, resource: str | None = None,
                           details: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = event(
        event_type,
        request_id=request_id,
        organization_id=organization_id,
        severity=severity,
        resource=resource,
        details=details or {},
    )
    payload["trace_context"] = new_trace_context().__dict__
    delivery = ROUTER.route(payload)
    payload["delivery"] = delivery
    return payload


def correlate_event(payload: dict[str, Any], *, trace_id: str, span_id: str) -> dict[str, Any]:
    correlated = dict(payload)
    correlated["trace_id"] = trace_id
    correlated["span_id"] = span_id
    return correlated
