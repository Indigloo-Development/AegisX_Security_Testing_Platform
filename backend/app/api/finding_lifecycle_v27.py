from __future__ import annotations
from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.lifecycle.service import upsert_lifecycle, compare_evidence, trend_summary, snapshot_trend
from app.lifecycle.models import FindingLifecycleStatus, FindingLifecycle, EvidenceSnapshot, RetestRecord

router = APIRouter(prefix="/api/finding-lifecycle-v27", tags=["finding-lifecycle-v27"])

class LifecycleBody(BaseModel):
    finding_key: str = Field(min_length=1, max_length=100)
    status: str = "open"
    scan_id: int | None = None
    risk_score: float = Field(default=0.0, ge=0, le=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    note: str | None = Field(default=None, max_length=2000)

class RetestBody(BaseModel):
    finding_key: str = Field(min_length=1, max_length=100)
    evidence: dict[str, Any] = Field(default_factory=dict)
    notes: str | None = Field(default=None, max_length=2000)

class TrendBody(BaseModel):
    period: str = Field(min_length=1, max_length=40)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=10000)

@router.post("/lifecycle")
def lifecycle(body: LifecycleBody, db: Session = Depends(get_db), _=Depends(get_local_operator)):
    if body.status not in {x.value for x in FindingLifecycleStatus}:
        return {"error": "invalid_status", "allowed": [x.value for x in FindingLifecycleStatus]}
    row = upsert_lifecycle(db, finding_key=body.finding_key, status=body.status, scan_id=body.scan_id,
                           evidence=body.evidence, risk_score=body.risk_score, note=body.note)
    return {"id": row.id, "finding_key": row.finding_key, "status": row.status.value,
            "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at, "risk_score": row.risk_score}

@router.get("/lifecycle/{finding_key}")
def get_lifecycle(finding_key: str, db: Session = Depends(get_db), _=Depends(get_local_operator)):
    row = db.query(FindingLifecycle).filter(FindingLifecycle.finding_key == finding_key).first()
    if not row: return {"finding_key": finding_key, "status": "unknown", "history": []}
    snapshots = db.query(EvidenceSnapshot).filter(EvidenceSnapshot.finding_key == finding_key).order_by(EvidenceSnapshot.observed_at.asc()).all()
    retests = db.query(RetestRecord).filter(RetestRecord.finding_key == finding_key).order_by(RetestRecord.compared_at.asc()).all()
    return {"finding_key": finding_key, "status": row.status.value, "first_seen_at": row.first_seen_at,
            "last_seen_at": row.last_seen_at, "risk_score": row.risk_score,
            "evidence_history": [{"observed_at": x.observed_at, "fingerprint": x.fingerprint} for x in snapshots],
            "retests": [{"compared_at": x.compared_at, "result": x.result, "diff": x.diff} for x in retests]}

@router.post("/retest")
def retest(body: RetestBody, db: Session = Depends(get_db), _=Depends(get_local_operator)):
    rec = compare_evidence(db, body.finding_key, body.evidence, notes=body.notes)
    return {"finding_key": rec.finding_key, "result": rec.result, "previous_status": rec.previous_status,
            "previous_fingerprint": rec.previous_fingerprint, "current_fingerprint": rec.current_fingerprint, "diff": rec.diff}

@router.post("/trend/snapshot")
def trend(body: TrendBody, db: Session = Depends(get_db), _=Depends(get_local_operator)):
    row = snapshot_trend(db, body.period, body.findings)
    return {"period": row.period, "risk_score": row.risk_score, "total_findings": row.total_findings,
            "critical": row.critical, "high": row.high, "medium": row.medium, "low": row.low, "info": row.info}

@router.get("/trend")
def get_trend(db: Session = Depends(get_db), _=Depends(get_local_operator)):
    return {"points": trend_summary(db)}
