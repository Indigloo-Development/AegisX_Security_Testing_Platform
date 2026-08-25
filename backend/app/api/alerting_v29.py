from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.alerting_v29 import AlertEvent, AlertDeduplicator, EmailAdapter, SlackAdapter, WebhookAdapter, build_monitoring_alerts, build_scan_alert

router = APIRouter(prefix="/api/alerting-v29", tags=["alerting-v29"])
_DEDUP = AlertDeduplicator()
_EVENTS: list[dict[str, Any]] = []
_CHANNELS = {"email": EmailAdapter(), "slack": SlackAdapter(), "webhook": WebhookAdapter()}

class MonitoringAlertBody(BaseModel):
    asset_id: str = Field(min_length=1, max_length=200)
    diff: dict[str, Any]
    minimum_severity: str = "medium"

class ScanFailureBody(BaseModel):
    scan_id: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=50)
    asset_id: str | None = None
    error: str | None = None

class NotifyBody(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=128)
    channels: list[str] = Field(default_factory=list, max_length=10)

@router.post("/events/monitoring")
def monitoring_alerts(body: MonitoringAlertBody, _=Depends(get_local_operator)):
    events = build_monitoring_alerts(body.diff, body.asset_id, body.minimum_severity)
    accepted = []
    for event in events:
        if _DEDUP.accept(event):
            payload = event.__dict__.copy(); payload["fingerprint"] = event.fingerprint
            _EVENTS.append(payload); accepted.append(payload)
    return {"accepted": accepted, "suppressed_duplicates": len(events) - len(accepted)}

@router.post("/events/scan-failure")
def scan_failure(body: ScanFailureBody, _=Depends(get_local_operator)):
    event = build_scan_alert(body.scan_id, body.status, asset_id=body.asset_id, error=body.error)
    if not event:
        return {"created": False}
    if not _DEDUP.accept(event):
        return {"created": False, "duplicate": True, "fingerprint": event.fingerprint}
    payload = event.__dict__.copy(); payload["fingerprint"] = event.fingerprint
    _EVENTS.append(payload)
    return {"created": True, "event": payload}

@router.get("/events")
def list_events(_=Depends(get_local_operator)):
    return {"events": list(_EVENTS), "count": len(_EVENTS)}

@router.post("/notify")
def notify(body: NotifyBody, _=Depends(get_local_operator)):
    event = next((x for x in _EVENTS if x.get("fingerprint") == body.fingerprint), None)
    if not event:
        raise HTTPException(status_code=404, detail="alert not found")
    model = AlertEvent(alert_type=event["alert_type"], severity=event["severity"], subject=event["subject"], asset_id=event.get("asset_id"), finding_key=event.get("finding_key"), message=event.get("message", ""), metadata=event.get("metadata", {}), created_at=event.get("created_at"))
    channels = body.channels or ["webhook"]
    results = []
    for channel in channels:
        adapter = _CHANNELS.get(channel)
        if not adapter:
            raise HTTPException(status_code=400, detail=f"unsupported channel: {channel}")
        results.append(adapter.send(model))
    return {"fingerprint": body.fingerprint, "results": results}

@router.post("/clear-dedup")
def clear_dedup(_=Depends(get_local_operator)):
    _DEDUP.clear()
    return {"cleared": True}
