from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models.models import User, IncidentRecord, IncidentHistory, RemediationRecord, TicketLink
from app.enterprise_v37.service import create_incident, assign, change_status, add_remediation, ticket_payload, link_ticket, inbound_sync

router = APIRouter(prefix="/api/enterprise-v37", tags=["enterprise-v37"])

class IncidentBody(BaseModel):
    incident_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=300)
    severity: str = "medium"
    finding_keys: list[str] = Field(default_factory=list, max_length=100)

class AssignBody(BaseModel): owner: str = Field(min_length=1, max_length=320)
class StatusBody(BaseModel): status: str
class RemediationBody(BaseModel):
    owner: str = Field(min_length=1, max_length=320)
    action: str = Field(min_length=1, max_length=2000)
    due_at: datetime | None = None
class TicketBody(BaseModel):
    provider: str = Field(pattern="^(jira|servicenow)$")
    external_key: str = Field(min_length=1, max_length=128)
    external_status: str = Field(min_length=1, max_length=64)
    url: str | None = None
class SyncBody(BaseModel):
    provider: str = Field(pattern="^(jira|servicenow)$")
    external_status: str = Field(min_length=1, max_length=64)
class TicketPayloadBody(BaseModel):
    provider: str = Field(pattern="^(jira|servicenow)$")


def _incident(db: Session, incident_id: str, user: User) -> IncidentRecord:
    rec = db.query(IncidentRecord).filter(IncidentRecord.incident_id == incident_id, IncidentRecord.organization_id == user.organization_id).one_or_none()
    if not rec:
        raise HTTPException(404, "incident not found")
    return rec

@router.post("/incidents")
def create(body: IncidentBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try: return create_incident(db, user.organization_id, body.incident_id, body.title, body.severity, body.finding_keys).__dict__
    except Exception as exc: raise HTTPException(409, str(exc)) from exc

@router.get("/incidents")
def list_incidents(user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    rows = db.query(IncidentRecord).filter(IncidentRecord.organization_id == user.organization_id).order_by(IncidentRecord.created_at.desc()).all()
    return {"items": [x.__dict__ for x in rows]}

@router.get("/incidents/{incident_id}/history")
def history(incident_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    _incident(db, incident_id, user)
    rows = db.query(IncidentHistory).filter(IncidentHistory.incident_id == incident_id, IncidentHistory.organization_id == user.organization_id).order_by(IncidentHistory.created_at.asc()).all()
    return {"items": [x.__dict__ for x in rows]}

@router.post("/incidents/{incident_id}/assign")
def assign_route(incident_id: str, body: AssignBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    return assign(db, _incident(db, incident_id, user), body.owner, user.id).__dict__

@router.post("/incidents/{incident_id}/transition")
def transition(incident_id: str, body: StatusBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try: return change_status(db, _incident(db, incident_id, user), body.status, user.id).__dict__
    except ValueError as exc: raise HTTPException(409, str(exc)) from exc

@router.post("/incidents/{incident_id}/remediation")
def remediation(incident_id: str, body: RemediationBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    return add_remediation(db, _incident(db, incident_id, user), body.owner, body.action, body.due_at, user.id).__dict__

@router.post("/incidents/{incident_id}/ticket")
def ticket_payload_route(incident_id: str, body: TicketPayloadBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    rec = _incident(db, incident_id, user)
    return ticket_payload(rec, body.provider).__dict__

@router.post("/incidents/{incident_id}/ticket/link")
def ticket_link_route(incident_id: str, body: TicketBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    rec = _incident(db, incident_id, user)
    return link_ticket(db, rec, body.provider, body.external_key, body.external_status, body.url, user.id).__dict__

@router.post("/incidents/{incident_id}/ticket/sync")
def ticket_sync(incident_id: str, body: SyncBody, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try: return inbound_sync(db, _incident(db, incident_id, user), body.provider, body.external_status, user.id).__dict__
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc

@router.get("/incidents/{incident_id}/tickets")
def tickets(incident_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    _incident(db, incident_id, user)
    rows = db.query(TicketLink).filter(TicketLink.incident_id == incident_id, TicketLink.organization_id == user.organization_id).all()
    return {"items": [x.__dict__ for x in rows]}

@router.get("/incidents/{incident_id}/remediation")
def remediations(incident_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    _incident(db, incident_id, user)
    rows = db.query(RemediationRecord).filter(RemediationRecord.incident_id == incident_id, RemediationRecord.organization_id == user.organization_id).all()
    return {"items": [x.__dict__ for x in rows]}
