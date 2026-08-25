from __future__ import annotations

import json
import logging
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator


log = logging.getLogger("aegisx.observability")

_counters: dict[str, int] = {}
_gauges: dict[str, float] = {"aegisx_up": 1.0, "aegisx_http_active_requests": 0.0, "aegisx_queue_depth": 0.0}
_histograms: dict[str, list[float]] = {}

def _inc(name: str, amount: int = 1) -> None:
    _counters[name] = _counters.get(name, 0) + amount

def _observe(name: str, value: float) -> None:
    _histograms.setdefault(name, []).append(float(value))

def _set(name: str, value: float) -> None:
    _gauges[name] = float(value)

# Compatibility-friendly metric names exposed through the local /metrics endpoint.
HTTP_REQUESTS = type("CounterHandle", (), {"labels": lambda self, **_: type("L", (), {"inc": lambda _s: _inc("aegisx_http_requests_total")})()})()
HTTP_LATENCY = type("HistogramHandle", (), {"labels": lambda self, **_: type("L", (), {"observe": lambda _s, value: _observe("aegisx_http_request_duration_seconds", value)})()})()
ACTIVE_REQUESTS = type("GaugeHandle", (), {"inc": lambda self: _set("aegisx_http_active_requests", _gauges.get("aegisx_http_active_requests", 0)+1), "dec": lambda self: _set("aegisx_http_active_requests", max(0, _gauges.get("aegisx_http_active_requests", 0)-1)), "set": lambda self, value: _set("aegisx_http_active_requests", value)})()
SCAN_STARTED = type("CounterHandle", (), {"labels": lambda self, **_: type("L", (), {"inc": lambda _s: _inc("aegisx_scans_started_total")})()})()
SCAN_COMPLETED = type("CounterHandle", (), {"labels": lambda self, **_: type("L", (), {"inc": lambda _s: _inc("aegisx_scans_completed_total")})()})()
FINDINGS_CREATED = type("CounterHandle", (), {"labels": lambda self, **_: type("L", (), {"inc": lambda _s: _inc("aegisx_findings_created_total")})()})()
WORKER_JOBS = type("CounterHandle", (), {"labels": lambda self, **_: type("L", (), {"inc": lambda _s: _inc("aegisx_worker_jobs_total")})()})()
QUEUE_DEPTH = type("GaugeHandle", (), {"labels": lambda self, **_: type("L", (), {"set": lambda _s, value: _set("aegisx_queue_depth", value)})()})()
APP_UP = type("GaugeHandle", (), {"set": lambda self, value: _set("aegisx_up", value)})()
APP_UP.set(1)


def path_template(request: Any) -> str:
    route = getattr(request, "scope", {}).get("route")
    return getattr(route, "path", None) or getattr(request.url, "path", "unknown")


def event(event_type: str, *, request_id: str | None = None, actor: str | None = None,
          organization_id: str | None = None, **fields: Any) -> dict[str, Any]:
    payload = {
        "event_type": event_type,
        "event_id": uuid.uuid4().hex,
        "timestamp": time.time(),
    }
    if request_id:
        payload["request_id"] = request_id
    if actor:
        payload["actor"] = actor
    if organization_id:
        payload["organization_id"] = organization_id
    payload.update({k: v for k, v in fields.items() if v is not None})
    log.info("security_event", extra={"event": payload})
    return payload


def mark_scan(scanner_type: str, status: str) -> None:
    if status == "started":
        SCAN_STARTED.labels(scanner_type=scanner_type).inc()
    else:
        SCAN_COMPLETED.labels(scanner_type=scanner_type, status=status).inc()


def mark_finding(severity: str, family: str) -> None:
    FINDINGS_CREATED.labels(severity=severity.upper(), family=family).inc()


@contextmanager
def trace_span(name: str, **attributes: Any) -> Iterator[dict[str, Any]]:
    start = time.perf_counter()
    trace_id = uuid.uuid4().hex
    span = {"trace_id": trace_id, "span_name": name, "start": start, "attributes": attributes}
    try:
        yield span
    finally:
        span["duration_ms"] = round((time.perf_counter() - start) * 1000, 3)
        log.debug("trace_span", extra={"event": span})


def metrics_payload() -> tuple[bytes, str]:
    lines: list[str] = []
    for name, value in sorted(_gauges.items()):
        lines.append(f"{name} {value:g}")
    for name, value in sorted(_counters.items()):
        lines.append(f"{name} {value:g}")
    for name, values in sorted(_histograms.items()):
        lines.append(f"{name}_count {len(values)}")
        lines.append(f"{name}_sum {sum(values):.6f}")
    lines.append("# Local AegisX metrics endpoint; no external metrics service required.")
    return ("\n".join(lines) + "\n").encode("utf-8"), "text/plain"
