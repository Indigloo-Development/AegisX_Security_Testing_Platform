from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from app.api.deps import get_local_operator
from app.models.models import User
from app.incident_response_v36 import Incident, IncidentSeverity, manager, sla_breached, next_escalation_level

router = APIRouter(prefix="/api/security-operations-v36", tags=["security-operations-v36"])

class IncidentBody(BaseModel):
    incident_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    severity: str = "medium"
    finding_keys: list[str] = Field(default_factory=list, max_length=100)

class AssignBody(BaseModel):
    owner: str = Field(min_length=1, max_length=200)

class TransitionBody(BaseModel):
    status: str

class SuppressBody(BaseModel):
    fingerprint: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=1000)

class RemediationBody(BaseModel):
    owner: str = Field(min_length=1, max_length=200)
    action: str = Field(min_length=1, max_length=1000)
    due_at: str | None = None

@router.post("/incidents")
def create_incident(body: IncidentBody, user: User = Depends(get_local_operator)):
    if body.severity not in {x.value for x in IncidentSeverity}:
        raise HTTPException(400, "invalid severity")
    incident = Incident(body.incident_id, user.organization_id, body.title, body.severity, finding_keys=body.finding_keys)
    manager.create(incident)
    return incident.__dict__

@router.get("/incidents")
def list_incidents(user: User = Depends(get_local_operator)):
    return {"items": [x.__dict__ for x in manager.incidents.values() if x.organization_id == user.organization_id]}

@router.post("/incidents/{incident_id}/assign")
def assign_incident(incident_id: str, body: AssignBody, user: User = Depends(get_local_operator)):
    incident = manager.incidents.get(incident_id)
    if not incident or incident.organization_id != user.organization_id:
        raise HTTPException(404, "incident not found")
    return manager.assign(incident_id, body.owner).__dict__

@router.post("/incidents/{incident_id}/transition")
def transition_incident(incident_id: str, body: TransitionBody, user: User = Depends(get_local_operator)):
    incident = manager.incidents.get(incident_id)
    if not incident or incident.organization_id != user.organization_id:
        raise HTTPException(404, "incident not found")
    try:
        return manager.transition(incident_id, body.status).__dict__
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@router.post("/incidents/{incident_id}/remediation")
def add_remediation(incident_id: str, body: RemediationBody, user: User = Depends(get_local_operator)):
    incident = manager.incidents.get(incident_id)
    if not incident or incident.organization_id != user.organization_id:
        raise HTTPException(404, "incident not found")
    return manager.add_remediation(incident_id, body.owner, body.action, body.due_at).__dict__

@router.post("/suppression")
def suppress(body: SuppressBody, user: User = Depends(get_local_operator)):
    manager.suppress(body.fingerprint, body.reason)
    return {"fingerprint": body.fingerprint, "suppressed": True, "reason": body.reason}

@router.post("/escalate")
def escalate(user: User = Depends(get_local_operator)):
    updated = [x.__dict__ for x in manager.escalate_due() if x.organization_id == user.organization_id]
    return {"escalated": updated, "count": len(updated)}

@router.get("/sla/{incident_id}")
def sla(incident_id: str, user: User = Depends(get_local_operator)):
    incident = manager.incidents.get(incident_id)
    if not incident or incident.organization_id != user.organization_id:
        raise HTTPException(404, "incident not found")
    return {"incident_id": incident_id, "breached": sla_breached(incident), "escalation_level": next_escalation_level(incident), "due_at": incident.due_at}

@router.post("/incidents/{incident_id}/close")
def close(incident_id: str, user: User = Depends(get_local_operator)):
    incident = manager.incidents.get(incident_id)
    if not incident or incident.organization_id != user.organization_id:
        raise HTTPException(404, "incident not found")
    try:
        return manager.close_if_resolved(incident_id).__dict__
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
