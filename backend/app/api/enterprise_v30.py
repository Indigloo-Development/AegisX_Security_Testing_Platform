from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models.models import User
from app.enterprise_v30 import Permission, authorize, queue, quotas, Quota, hash_secret

router = APIRouter(prefix='/api/enterprise-v30', tags=['enterprise-v30'])

class WorkspaceRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)

class QueueRequest(BaseModel):
    job_id: str = Field(min_length=1, max_length=128)
    priority: int = Field(default=50, ge=1, le=100)

class SecretRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    value: str = Field(min_length=1, max_length=4096)

class QuotaRequest(BaseModel):
    max_concurrent_scans: int = Field(default=4, ge=1, le=100)
    max_targets: int = Field(default=100, ge=1, le=100000)
    max_scheduled_scans: int = Field(default=50, ge=1, le=10000)

@router.get('/tenant-context')
def tenant_context(user: User = Depends(get_local_operator)):
    return {'organization_id': user.organization_id, 'role': user.role.value, 'isolation': 'enforced'}

@router.post('/authorize')
def authorization(resource_org_id: int, action: Permission, user: User = Depends(get_local_operator)):
    return authorize(user.role.value, action, resource_org_id, user.organization_id).__dict__

@router.post('/queue/submit')
def queue_submit(body: QueueRequest, user: User = Depends(get_local_operator)):
    decision = authorize(user.role.value, Permission.SCAN, user.organization_id, user.organization_id)
    if not decision.allowed: raise HTTPException(403, decision.reason)
    if not quotas.can_start(user.organization_id, Quota()):
        raise HTTPException(429, 'tenant scan concurrency quota exceeded')
    rec = queue.submit(body.job_id, user.organization_id, body.priority)
    return rec.__dict__

@router.post('/queue/claim')
def queue_claim(worker_id: str, user: User = Depends(get_local_operator)):
    if user.role.value not in {'admin','analyst'}: raise HTTPException(403, 'worker claim requires analyst/admin')
    rec = queue.claim(worker_id, user.organization_id)
    return None if rec is None else rec.__dict__

@router.post('/queue/complete')
def queue_complete(job_id: str, success: bool = True, user: User = Depends(get_local_operator)):
    rec = queue.jobs.get(job_id)
    if not rec or rec.organization_id != user.organization_id: raise HTTPException(404, 'job not found')
    return queue.complete(job_id, success).__dict__

@router.post('/quota/check')
def quota_check(body: QuotaRequest, user: User = Depends(get_local_operator)):
    quota = Quota(**body.model_dump())
    return {'organization_id': user.organization_id, 'can_start': quotas.can_start(user.organization_id, quota), 'quota': quota.__dict__}

@router.post('/secrets/hash')
def secret_hash(body: SecretRequest, user: User = Depends(get_local_operator)):
    if user.role.value != 'admin': raise HTTPException(403, 'admin role required')
    salt, digest = hash_secret(body.value)
    return {'name': body.name, 'organization_id': user.organization_id, 'salt': salt, 'digest': digest, 'storage': 'hash-only-demo'}
