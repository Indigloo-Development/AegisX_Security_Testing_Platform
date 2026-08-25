from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.monitoring_v28 import normalize_snapshot, compare_snapshots, build_alerts, detect_shadow_assets

router = APIRouter(prefix="/api/monitoring-v28", tags=["monitoring-v28"])

_SNAPSHOTS: dict[str, dict[str, Any]] = {}
_SCHEDULES: dict[str, dict[str, Any]] = {}

class SnapshotBody(BaseModel):
    asset_id: str = Field(min_length=1, max_length=200)
    asset_type: str = "web"
    target: str = Field(min_length=1, max_length=2048)
    endpoints: list[str] = Field(default_factory=list, max_length=5000)
    technologies: list[str] = Field(default_factory=list, max_length=1000)
    dependencies: list[str] = Field(default_factory=list, max_length=5000)
    metadata: dict[str, Any] = Field(default_factory=dict)
    observed_at: str | None = None

class ShadowBody(BaseModel):
    known_targets: list[str] = Field(default_factory=list, max_length=5000)
    observed_targets: list[str] = Field(default_factory=list, max_length=5000)

class ScheduleBody(BaseModel):
    schedule_id: str = Field(min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=2048)
    cadence: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    profile: str = "standard"

@router.post("/assets/snapshot")
def asset_snapshot(body: SnapshotBody, _=Depends(get_local_operator)):
    current = normalize_snapshot(body.model_dump())
    previous_payload = _SNAPSHOTS.get(current.asset_id)
    previous = normalize_snapshot(previous_payload) if previous_payload else None
    diff = compare_snapshots(previous, current)
    alerts = build_alerts(diff, asset_id=current.asset_id)
    _SNAPSHOTS[current.asset_id] = body.model_dump()
    return {"asset_id": current.asset_id, "fingerprint": current.fingerprint, "diff": diff, "alerts": alerts}

@router.get("/assets")
def assets(_=Depends(get_local_operator)):
    return {"assets": list(_SNAPSHOTS.values()), "count": len(_SNAPSHOTS)}

@router.post("/shadow-assets")
def shadow_assets(body: ShadowBody, _=Depends(get_local_operator)):
    shadows = detect_shadow_assets(body.known_targets, body.observed_targets)
    return {"count": len(shadows), "shadow_assets": shadows, "severity": "high" if shadows else "info"}

@router.post("/schedules")
def create_schedule(body: ScheduleBody, _=Depends(get_local_operator)):
    _SCHEDULES[body.schedule_id] = body.model_dump()
    return _SCHEDULES[body.schedule_id]

@router.get("/schedules")
def list_schedules(_=Depends(get_local_operator)):
    return {"schedules": list(_SCHEDULES.values())}

@router.delete("/schedules/{schedule_id}")
def delete_schedule(schedule_id: str, _=Depends(get_local_operator)):
    if schedule_id not in _SCHEDULES:
        raise HTTPException(status_code=404, detail="schedule not found")
    _SCHEDULES.pop(schedule_id)
    return {"deleted": schedule_id}
