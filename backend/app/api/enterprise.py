from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models import User
from app.models.models import ApiKeyRecord, AuditEvent
from app.services.enterprise import create_api_key, add_audit_event, evaluate_security_gate

router = APIRouter(prefix="/api/enterprise", tags=["enterprise"])

class ApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = []

class GateRequest(BaseModel):
    findings: list[dict] = []
    policy: dict = {"max_severity_counts": {"critical": 0, "high": 0}}

class OIDCConfig(BaseModel):
    issuer_url: HttpUrl
    client_id: str
    scopes: list[str] = ["openid", "profile", "email"]

class WebhookConfig(BaseModel):
    provider: str
    webhook_url: HttpUrl

class JiraConfig(BaseModel):
    base_url: HttpUrl
    project_key: str
    issue_type: str = "Bug"

@router.post("/api-keys")
def issue_api_key(body: ApiKeyCreate, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    raw, record = create_api_key(db, body.name, user.id, body.scopes)
    add_audit_event(db, "api_key.created", user.id, user.organization_id, {"key_id": record.id, "name": record.name})
    return {"id": record.id, "name": record.name, "key": raw, "key_prefix": record.key_prefix, "scopes": record.scopes}

@router.get("/api-keys")
def list_api_keys(db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    rows = db.query(ApiKeyRecord).filter(ApiKeyRecord.owner_id == user.id).order_by(ApiKeyRecord.id.desc()).all()
    return [{"id": r.id, "name": r.name, "key_prefix": r.key_prefix, "scopes": r.scopes, "revoked": r.revoked, "created_at": r.created_at, "last_used_at": r.last_used_at} for r in rows]

@router.post("/security-gate")
def security_gate(body: GateRequest, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    result = evaluate_security_gate(body.findings, body.policy)
    add_audit_event(db, "security_gate.evaluated", user.id, user.organization_id, result)
    return result

@router.get("/audit-events")
def audit_events(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(get_local_operator)):
    rows = db.query(AuditEvent).filter(AuditEvent.organization_id == user.organization_id).order_by(AuditEvent.id.desc()).limit(min(limit, 500)).all()
    return [{"id": r.id, "action": r.action, "actor_id": r.actor_id, "metadata": r.event_metadata, "created_at": r.created_at} for r in rows]

@router.post("/oidc/validate-config")
def validate_oidc(body: OIDCConfig):
    return {"valid": True, "issuer_url": str(body.issuer_url).rstrip("/"), "client_id": body.client_id, "scopes": body.scopes, "mode": "discovery-ready"}

@router.post("/integrations/webhook/validate")
def validate_webhook(body: WebhookConfig):
    allowed = {"github", "gitlab", "jenkins", "slack", "generic"}
    if body.provider.lower() not in allowed:
        raise HTTPException(400, "Unsupported webhook provider")
    return {"valid": True, "provider": body.provider.lower(), "webhook_url": str(body.webhook_url)}

@router.post("/integrations/jira/validate")
def validate_jira(body: JiraConfig):
    return {"valid": True, "base_url": str(body.base_url).rstrip("/"), "project_key": body.project_key, "issue_type": body.issue_type, "mode": "adapter-ready"}
