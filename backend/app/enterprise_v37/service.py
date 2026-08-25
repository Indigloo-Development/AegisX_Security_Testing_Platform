from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Any

from sqlalchemy.orm import Session
from app.models.models import IncidentRecord, IncidentHistory, RemediationRecord, TicketLink, TicketSyncEvent

SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168}

@dataclass
class TicketPayload:
    provider: str
    external_key: str
    title: str
    description: str
    severity: str
    status: str


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def incident_fingerprint(org_id: int, title: str, severity: str, findings: list[str]) -> str:
    raw = f"{org_id}|{title.strip().lower()}|{severity}|{','.join(sorted(findings))}"
    return sha256(raw.encode()).hexdigest()


def create_incident(db: Session, org_id: int, incident_id: str, title: str, severity: str, finding_keys: list[str]) -> IncidentRecord:
    now = _now()
    due = now + timedelta(hours=SLA_HOURS.get(severity, 72))
    rec = IncidentRecord(
        incident_id=incident_id,
        organization_id=org_id,
        title=title,
        severity=severity,
        status="open",
        finding_keys=finding_keys,
        fingerprint=incident_fingerprint(org_id, title, severity, finding_keys),
        created_at=now,
        updated_at=now,
        due_at=due,
    )
    db.add(rec)
    db.add(IncidentHistory(incident_id=incident_id, organization_id=org_id, event_type="created", new_status="open", metadata={}, created_at=now))
    db.commit(); db.refresh(rec)
    return rec


def add_history(db: Session, rec: IncidentRecord, event_type: str, actor_id: int | None, old_status: str | None, new_status: str | None, metadata: dict[str, Any] | None = None) -> None:
    db.add(IncidentHistory(incident_id=rec.incident_id, organization_id=rec.organization_id, event_type=event_type, actor_id=actor_id, old_status=old_status, new_status=new_status, event_metadata=metadata or {}, created_at=_now()))


def change_status(db: Session, rec: IncidentRecord, status: str, actor_id: int | None) -> IncidentRecord:
    allowed = {"open", "in_progress", "resolved", "closed"}
    if status not in allowed:
        raise ValueError("invalid incident status")
    old = rec.status
    if status == "closed":
        open_tasks = db.query(RemediationRecord).filter(RemediationRecord.incident_id == rec.incident_id, RemediationRecord.status != "completed").count()
        if open_tasks:
            raise ValueError("remediation tasks remain open")
    rec.status = status
    rec.updated_at = _now()
    add_history(db, rec, "status_changed", actor_id, old, status)
    db.commit(); db.refresh(rec)
    return rec


def assign(db: Session, rec: IncidentRecord, owner: str, actor_id: int | None) -> IncidentRecord:
    rec.owner = owner
    old = rec.status
    if old == "open": rec.status = "in_progress"
    rec.updated_at = _now()
    add_history(db, rec, "assigned", actor_id, old, rec.status, {"owner": owner})
    db.commit(); db.refresh(rec)
    return rec


def add_remediation(db: Session, rec: IncidentRecord, owner: str, action: str, due_at: datetime | None, actor_id: int | None) -> RemediationRecord:
    task_id = sha256(f"{rec.incident_id}|{owner}|{action}".encode()).hexdigest()[:24]
    task = RemediationRecord(task_id=task_id, incident_id=rec.incident_id, organization_id=rec.organization_id, owner=owner, action=action, status="open", due_at=due_at, created_at=_now(), updated_at=_now())
    db.add(task); add_history(db, rec, "remediation_added", actor_id, rec.status, rec.status, {"task_id": task_id})
    db.commit(); db.refresh(task)
    return task


def ticket_payload(rec: IncidentRecord, provider: str) -> TicketPayload:
    provider = provider.lower()
    external_key = f"AEGISX-{rec.incident_id}"
    description = f"AegisX incident {rec.incident_id}\nSeverity: {rec.severity}\nStatus: {rec.status}\nFinding keys: {', '.join(rec.finding_keys or [])}"
    return TicketPayload(provider=provider, external_key=external_key, title=rec.title, description=description, severity=rec.severity, status=rec.status)


def link_ticket(db: Session, rec: IncidentRecord, provider: str, external_key: str, external_status: str, url: str | None, actor_id: int | None) -> TicketLink:
    link = db.query(TicketLink).filter(TicketLink.incident_id == rec.incident_id, TicketLink.provider == provider).one_or_none()
    if link is None:
        link = TicketLink(incident_id=rec.incident_id, organization_id=rec.organization_id, provider=provider, external_key=external_key, external_status=external_status, url=url, created_at=_now(), updated_at=_now())
        db.add(link)
    else:
        link.external_key = external_key; link.external_status = external_status; link.url = url; link.updated_at = _now()
    db.add(TicketSyncEvent(incident_id=rec.incident_id, organization_id=rec.organization_id, provider=provider, direction="outbound", external_status=external_status, local_status=rec.status, payload={}, created_at=_now(), actor_id=actor_id))
    db.commit(); db.refresh(link)
    return link


def inbound_sync(db: Session, rec: IncidentRecord, provider: str, external_status: str, actor_id: int | None) -> IncidentRecord:
    mapped = {"open": "open", "new": "open", "todo": "open", "in_progress": "in_progress", "working": "in_progress", "resolved": "resolved", "done": "resolved", "closed": "closed"}.get(external_status.lower())
    if not mapped:
        raise ValueError("unsupported external status")
    return change_status(db, rec, mapped, actor_id)
