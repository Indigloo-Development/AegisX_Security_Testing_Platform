from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from hashlib import sha256
from typing import Any

class IncidentStatus(str, Enum):
    open = "open"
    in_progress = "in_progress"
    resolved = "resolved"
    closed = "closed"

class IncidentSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"

SEVERITY_SLA_HOURS = {"critical": 4, "high": 24, "medium": 72, "low": 168}

@dataclass
class Incident:
    incident_id: str
    organization_id: int
    title: str
    severity: str
    status: str = IncidentStatus.open.value
    owner: str | None = None
    finding_keys: list[str] | None = None
    created_at: str = ""
    updated_at: str = ""
    due_at: str | None = None
    escalation_level: int = 0
    suppression_reason: str | None = None

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc)
        if not self.created_at:
            self.created_at = now.isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at
        if not self.due_at:
            self.due_at = (now + timedelta(hours=SEVERITY_SLA_HOURS.get(self.severity, 72))).isoformat()
        if self.finding_keys is None:
            self.finding_keys = []

    @property
    def fingerprint(self) -> str:
        raw = f"{self.organization_id}|{self.title.lower().strip()}|{self.severity}|{','.join(sorted(self.finding_keys or []))}"
        return sha256(raw.encode()).hexdigest()

def sla_breached(incident: Incident, now: datetime | None = None) -> bool:
    if incident.status in {IncidentStatus.resolved.value, IncidentStatus.closed.value}:
        return False
    due = datetime.fromisoformat(incident.due_at) if incident.due_at else None
    return bool(due and (now or datetime.now(timezone.utc)) > due)

def next_escalation_level(incident: Incident, now: datetime | None = None) -> int:
    if not sla_breached(incident, now):
        return incident.escalation_level
    return min(3, incident.escalation_level + 1)

@dataclass
class RemediationTask:
    task_id: str
    incident_id: str
    owner: str
    action: str
    status: str = "open"
    due_at: str | None = None

class IncidentManager:
    def __init__(self) -> None:
        self.incidents: dict[str, Incident] = {}
        self.remediation: dict[str, RemediationTask] = {}
        self.suppressed: set[str] = set()

    def create(self, incident: Incident) -> Incident:
        if incident.fingerprint in self.suppressed:
            incident.suppression_reason = "matching fingerprint suppressed"
        self.incidents[incident.incident_id] = incident
        return incident

    def assign(self, incident_id: str, owner: str) -> Incident:
        incident = self.incidents[incident_id]
        incident.owner = owner
        incident.status = IncidentStatus.in_progress.value
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        return incident

    def transition(self, incident_id: str, status: str) -> Incident:
        if status not in {s.value for s in IncidentStatus}:
            raise ValueError("invalid incident status")
        incident = self.incidents[incident_id]
        incident.status = status
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        return incident

    def suppress(self, fingerprint: str, reason: str) -> None:
        if not reason.strip():
            raise ValueError("suppression reason required")
        self.suppressed.add(fingerprint)

    def escalate_due(self, now: datetime | None = None) -> list[Incident]:
        updated = []
        for incident in self.incidents.values():
            level = next_escalation_level(incident, now)
            if level > incident.escalation_level:
                incident.escalation_level = level
                incident.updated_at = datetime.now(timezone.utc).isoformat()
                updated.append(incident)
        return updated

    def add_remediation(self, incident_id: str, owner: str, action: str, due_at: str | None = None) -> RemediationTask:
        task_id = sha256(f"{incident_id}|{owner}|{action}".encode()).hexdigest()[:20]
        task = RemediationTask(task_id, incident_id, owner, action, due_at=due_at)
        self.remediation[task_id] = task
        return task

    def close_if_resolved(self, incident_id: str) -> Incident:
        incident = self.incidents[incident_id]
        open_tasks = [t for t in self.remediation.values() if t.incident_id == incident_id and t.status != "completed"]
        if open_tasks:
            raise ValueError("remediation tasks remain open")
        incident.status = IncidentStatus.closed.value
        incident.updated_at = datetime.now(timezone.utc).isoformat()
        return incident

manager = IncidentManager()
