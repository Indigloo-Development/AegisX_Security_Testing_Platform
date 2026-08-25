import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.models import AuditEvent, ApiKeyRecord


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_api_key(db: Session, name: str, owner_id: int, scopes: list[str]) -> tuple[str, ApiKeyRecord]:
    prefix = "ax_"
    raw = prefix + secrets.token_urlsafe(32)
    record = ApiKeyRecord(
        name=name,
        key_hash=hash_api_key(raw),
        key_prefix=raw[:10],
        owner_id=owner_id,
        scopes=scopes,
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return raw, record


def verify_api_key(db: Session, raw: str) -> ApiKeyRecord | None:
    digest = hash_api_key(raw)
    records = db.query(ApiKeyRecord).filter(ApiKeyRecord.revoked.is_(False)).all()
    for record in records:
        if hmac.compare_digest(record.key_hash, digest):
            record.last_used_at = datetime.now(timezone.utc)
            db.commit()
            return record
    return None


def add_audit_event(db: Session, action: str, actor_id: int | None, organization_id: int | None, metadata: dict[str, Any] | None = None) -> AuditEvent:
    event = AuditEvent(
        action=action,
        actor_id=actor_id,
        organization_id=organization_id,
        event_metadata=metadata or {},
        created_at=datetime.now(timezone.utc),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def evaluate_security_gate(findings: list[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    max_counts = {k: int(v) for k, v in policy.get("max_severity_counts", {}).items()}
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    violations = []
    for sev, maximum in max_counts.items():
        if counts.get(sev.lower(), 0) > maximum:
            violations.append(f"{sev} findings {counts.get(sev.lower(), 0)} > allowed {maximum}")
    return {"passed": not violations, "violations": violations, "counts": counts}
