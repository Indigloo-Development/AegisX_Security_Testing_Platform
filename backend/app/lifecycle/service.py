from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone, timezone
from collections import Counter
from sqlalchemy.orm import Session
from .models import FindingLifecycle, FindingLifecycleStatus, EvidenceSnapshot, RetestRecord, RiskTrendPoint

SEV_WEIGHT = {"critical": 10.0, "high": 6.0, "medium": 3.0, "low": 1.0, "info": 0.0}

def evidence_fingerprint(evidence: dict) -> str:
    raw = json.dumps(evidence or {}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode()).hexdigest()

def upsert_lifecycle(db: Session, *, finding_key: str, status: str = "open", scan_id: int | None = None,
                     evidence: dict | None = None, risk_score: float = 0.0, note: str | None = None) -> FindingLifecycle:
    now = datetime.now(timezone.utc)
    row = db.query(FindingLifecycle).filter(FindingLifecycle.finding_key == finding_key).first()
    if row is None:
        row = FindingLifecycle(finding_key=finding_key, status=FindingLifecycleStatus(status), first_seen_at=now,
                               last_seen_at=now, last_scan_id=scan_id, risk_score=risk_score, status_reason=note)
        db.add(row)
    else:
        row.last_seen_at = now
        row.last_scan_id = scan_id or row.last_scan_id
        row.risk_score = risk_score
        if status in FindingLifecycleStatus.__members__ and status != row.status.value:
            row.status = FindingLifecycleStatus(status)
        if note:
            row.status_reason = note
    if evidence is not None:
        fp = evidence_fingerprint(evidence)
        db.add(EvidenceSnapshot(finding_key=finding_key, observed_at=now, evidence=evidence, fingerprint=fp, source_scan_id=scan_id))
    db.commit(); db.refresh(row)
    return row

def compare_evidence(db: Session, finding_key: str, current_evidence: dict, *, current_status: str | None = None, notes: str | None = None) -> RetestRecord:
    prev = db.query(EvidenceSnapshot).filter(EvidenceSnapshot.finding_key == finding_key).order_by(EvidenceSnapshot.observed_at.desc()).first()
    current_fp = evidence_fingerprint(current_evidence)
    previous_fp = prev.fingerprint if prev else None
    result = "not_reproduced" if not prev else ("unchanged" if current_fp == previous_fp else "changed")
    old_status = db.query(FindingLifecycle).filter(FindingLifecycle.finding_key == finding_key).first()
    previous_status = old_status.status.value if old_status else "unknown"
    diff = {"fingerprint_changed": previous_fp != current_fp, "previous": prev.evidence if prev else None, "current": current_evidence}
    rec = RetestRecord(finding_key=finding_key, previous_status=previous_status, result=result, previous_fingerprint=previous_fp,
                       current_fingerprint=current_fp, diff=diff, notes=notes)
    db.add(rec)
    if result == "not_reproduced" and old_status:
        old_status.status = FindingLifecycleStatus.fixed
    elif result in {"unchanged", "changed"} and old_status and old_status.status == FindingLifecycleStatus.fixed:
        old_status.status = FindingLifecycleStatus.reopened
    db.add(EvidenceSnapshot(finding_key=finding_key, evidence=current_evidence, fingerprint=current_fp))
    db.commit(); db.refresh(rec)
    return rec

def trend_summary(db: Session, periods: list[str] | None = None) -> list[dict]:
    rows = db.query(RiskTrendPoint).order_by(RiskTrendPoint.period.asc()).all()
    if periods:
        wanted = set(periods); rows = [r for r in rows if r.period in wanted]
    return [{"period": r.period, "total_findings": r.total_findings, "critical": r.critical, "high": r.high,
             "medium": r.medium, "low": r.low, "info": r.info, "risk_score": r.risk_score} for r in rows]

def snapshot_trend(db: Session, period: str, findings: list[dict]) -> RiskTrendPoint:
    counts = Counter(str(f.get("severity", "info")).lower() for f in findings)
    score = sum(SEV_WEIGHT.get(str(f.get("severity", "info")).lower(), 0.0) for f in findings)
    row = db.query(RiskTrendPoint).filter(RiskTrendPoint.period == period).first()
    values = dict(total_findings=len(findings), critical=counts.get("critical", 0), high=counts.get("high", 0),
                  medium=counts.get("medium", 0), low=counts.get("low", 0), info=counts.get("info", 0), risk_score=score)
    if row is None:
        row = RiskTrendPoint(period=period, **values); db.add(row)
    else:
        for k,v in values.items(): setattr(row, k, v)
    db.commit(); db.refresh(row); return row
