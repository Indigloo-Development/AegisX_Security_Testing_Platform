from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.api.deps import get_local_operator
from app.db.session import get_db
from app.models.models import User
from app.enterprise_v31 import JobState, queue_v31, workers_v31

router = APIRouter(prefix='/api/enterprise-v31', tags=['enterprise-v31'])

class SubmitRequest(BaseModel):
    job_id: str = Field(min_length=1, max_length=128)
    priority: int = Field(default=50, ge=1, le=100)
    payload: dict = Field(default_factory=dict)
    max_attempts: int = Field(default=3, ge=1, le=10)

@router.post('/jobs')
def submit_job(body: SubmitRequest, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    if user.role.value not in {'admin', 'analyst'}:
        raise HTTPException(403, 'scan permission required')
    try:
        job = queue_v31.submit(db, job_id=body.job_id, organization_id=user.organization_id, payload=body.payload, priority=body.priority, max_attempts=body.max_attempts)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _job(job)

@router.get('/jobs/{job_id}')
def get_job(job_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    from app.models.models import DistributedJob
    job = db.get(DistributedJob, job_id)
    if not job or job.organization_id != user.organization_id:
        raise HTTPException(404, 'job not found')
    return _job(job)

@router.post('/jobs/{job_id}/claim')
def claim_job(job_id: str, worker_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    if user.role.value not in {'admin', 'analyst'}:
        raise HTTPException(403, 'worker claim requires analyst/admin')
    job = queue_v31.claim(db, worker_id=worker_id, organization_id=user.organization_id)
    if not job or job.job_id != job_id:
        return None
    return _job(job)

@router.post('/jobs/{job_id}/heartbeat')
def heartbeat(job_id: str, worker_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try:
        job = queue_v31.heartbeat(db, job_id=job_id, worker_id=worker_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    if job.organization_id != user.organization_id:
        raise HTTPException(403, 'tenant boundary')
    return _job(job)

class CompleteRequest(BaseModel):
    success: bool = True
    error: str | None = Field(default=None, max_length=4000)

@router.post('/jobs/{job_id}/complete')
def complete_job(job_id: str, body: CompleteRequest, worker_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try:
        job = queue_v31.complete(db, job_id=job_id, worker_id=worker_id, success=body.success, error=body.error)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    if job.organization_id != user.organization_id:
        raise HTTPException(403, 'tenant boundary')
    return _job(job)

@router.post('/jobs/{job_id}/fail')
def fail_job(job_id: str, worker_id: str, error: str = 'worker failure', user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try:
        job = queue_v31.fail_or_retry(db, job_id=job_id, worker_id=worker_id, error=error)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    if job.organization_id != user.organization_id:
        raise HTTPException(403, 'tenant boundary')
    return _job(job)

@router.post('/jobs/{job_id}/cancel')
def cancel_job(job_id: str, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    try:
        job = queue_v31.cancel(db, job_id=job_id, organization_id=user.organization_id)
    except KeyError as exc:
        raise HTTPException(404, str(exc)) from exc
    return _job(job)

@router.post('/workers/heartbeat')
def worker_heartbeat(worker_id: str, active_job: str | None = None, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    if user.role.value not in {'admin', 'analyst'}:
        raise HTTPException(403, 'worker access requires analyst/admin')
    lease = workers_v31.heartbeat(db, worker_id=worker_id, organization_id=user.organization_id, active_job=active_job)
    return {'worker_id': lease.worker_id, 'organization_id': lease.organization_id, 'job_id': lease.job_id, 'heartbeat_at': lease.heartbeat_at.isoformat()}

@router.get('/workers/healthy')
def healthy_workers(user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    rows = workers_v31.healthy(db, organization_id=user.organization_id)
    return [{'worker_id': r.worker_id, 'organization_id': r.organization_id, 'job_id': r.job_id, 'heartbeat_at': r.heartbeat_at.isoformat()} for r in rows]

@router.post('/reaper')
def reap(timeout_seconds: int = 120, user: User = Depends(get_local_operator), db: Session = Depends(get_db)):
    if user.role.value != 'admin':
        raise HTTPException(403, 'admin role required')
    recovered = queue_v31.reap_stale(db, timeout_seconds=max(10, min(timeout_seconds, 3600)))
    return {'recovered': [_job(j) for j in recovered], 'count': len(recovered)}

def _job(job):
    return {
        'job_id': job.job_id,
        'organization_id': job.organization_id,
        'priority': job.priority,
        'state': job.state,
        'attempts': job.attempts,
        'max_attempts': job.max_attempts,
        'worker_id': job.worker_id,
        'payload': job.payload,
        'error': job.error,
        'available_at': job.available_at.isoformat() if job.available_at else None,
        'created_at': job.created_at.isoformat() if job.created_at else None,
        'started_at': job.started_at.isoformat() if job.started_at else None,
        'heartbeat_at': job.heartbeat_at.isoformat() if job.heartbeat_at else None,
        'finished_at': job.finished_at.isoformat() if job.finished_at else None,
    }
