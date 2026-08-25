from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import Session

from app.models.models import DistributedJob, WorkerLease


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class JobState(str, Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"
    dead_letter = "dead_letter"
    cancelled = "cancelled"


@dataclass(frozen=True)
class JobResult:
    job_id: str
    state: str
    attempts: int
    worker_id: str | None
    tenant_id: int


class PersistentQueue:
    """DB-backed queue with a Redis/RabbitMQ-compatible service boundary.

    PostgreSQL deployments can use row-locking safely across worker processes;
    SQLite remains supported for local development/regression tests.
    """

    def submit(
        self,
        db: Session,
        *,
        job_id: str,
        organization_id: int,
        payload: dict,
        priority: int = 50,
        max_attempts: int = 3,
    ) -> DistributedJob:
        existing = db.get(DistributedJob, job_id)
        if existing:
            raise ValueError("job_id already exists")
        job = DistributedJob(
            job_id=job_id,
            organization_id=organization_id,
            priority=priority,
            payload=payload,
            max_attempts=max_attempts,
            state=JobState.queued.value,
            available_at=utcnow(),
            created_at=utcnow(),
            updated_at=utcnow(),
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def claim(self, db: Session, *, worker_id: str, organization_id: int) -> DistributedJob | None:
        now = utcnow()
        # SQLite-compatible two-step claim. PostgreSQL workers can safely wrap this
        # operation in SERIALIZABLE/row-locking transaction at the deployment layer.
        stmt = (
            select(DistributedJob)
            .where(
                and_(
                    DistributedJob.organization_id == organization_id,
                    DistributedJob.state == JobState.queued.value,
                    DistributedJob.available_at <= now,
                )
            )
            .order_by(DistributedJob.priority.desc(), DistributedJob.created_at.asc())
            .limit(1)
        )
        job = db.execute(stmt).scalar_one_or_none()
        if job is None:
            return None
        job.state = JobState.running.value
        job.worker_id = worker_id
        job.attempts += 1
        job.started_at = now
        job.heartbeat_at = now
        job.updated_at = now
        db.add(WorkerLease(worker_id=worker_id, organization_id=organization_id, job_id=job.job_id, heartbeat_at=now))
        db.commit()
        db.refresh(job)
        return job

    def heartbeat(self, db: Session, *, job_id: str, worker_id: str) -> DistributedJob:
        job = db.get(DistributedJob, job_id)
        if not job or job.state != JobState.running.value or job.worker_id != worker_id:
            raise KeyError("job not owned by worker")
        now = utcnow()
        job.heartbeat_at = now
        job.updated_at = now
        db.query(WorkerLease).filter(WorkerLease.job_id == job_id, WorkerLease.worker_id == worker_id).update({"heartbeat_at": now})
        db.commit()
        db.refresh(job)
        return job

    def complete(self, db: Session, *, job_id: str, worker_id: str, success: bool, error: str | None = None) -> DistributedJob:
        job = db.get(DistributedJob, job_id)
        if not job or job.worker_id != worker_id:
            raise KeyError("job not owned by worker")
        now = utcnow()
        job.state = JobState.completed.value if success else JobState.failed.value
        job.error = error
        job.finished_at = now if success else None
        job.updated_at = now
        db.query(WorkerLease).filter(WorkerLease.job_id == job_id, WorkerLease.worker_id == worker_id).delete(synchronize_session=False)
        db.commit()
        db.refresh(job)
        return job

    def fail_or_retry(self, db: Session, *, job_id: str, worker_id: str, error: str) -> DistributedJob:
        job = db.get(DistributedJob, job_id)
        if not job or job.worker_id != worker_id:
            raise KeyError("job not owned by worker")
        now = utcnow()
        job.error = error[:4000]
        if job.attempts >= job.max_attempts:
            job.state = JobState.dead_letter.value
            job.finished_at = now
        else:
            delay = min(300, 2 ** max(0, job.attempts - 1))
            job.state = JobState.queued.value
            job.available_at = now + timedelta(seconds=delay)
            job.worker_id = None
            job.heartbeat_at = None
        job.updated_at = now
        db.query(WorkerLease).filter(WorkerLease.job_id == job_id, WorkerLease.worker_id == worker_id).delete(synchronize_session=False)
        db.commit()
        db.refresh(job)
        return job

    def cancel(self, db: Session, *, job_id: str, organization_id: int) -> DistributedJob:
        job = db.get(DistributedJob, job_id)
        if not job or job.organization_id != organization_id:
            raise KeyError("job not found")
        if job.state in {JobState.completed.value, JobState.dead_letter.value, JobState.cancelled.value}:
            return job
        job.state = JobState.cancelled.value
        job.updated_at = utcnow()
        db.query(WorkerLease).filter(WorkerLease.job_id == job_id).delete(synchronize_session=False)
        db.commit()
        db.refresh(job)
        return job

    def reap_stale(self, db: Session, *, timeout_seconds: int = 120) -> list[DistributedJob]:
        cutoff = utcnow() - timedelta(seconds=timeout_seconds)
        stale = db.execute(
            select(DistributedJob).where(
                DistributedJob.state == JobState.running.value,
                or_(DistributedJob.heartbeat_at.is_(None), DistributedJob.heartbeat_at < cutoff),
            )
        ).scalars().all()
        recovered: list[DistributedJob] = []
        for job in stale:
            if job.attempts >= job.max_attempts:
                job.state = JobState.dead_letter.value
                job.finished_at = utcnow()
            else:
                job.state = JobState.queued.value
                job.worker_id = None
                job.available_at = utcnow()
                job.heartbeat_at = None
            job.updated_at = utcnow()
            recovered.append(job)
        db.query(WorkerLease).filter(WorkerLease.job_id.in_([j.job_id for j in stale])).delete(synchronize_session=False) if stale else None
        db.commit()
        return recovered


@dataclass(frozen=True)
class WorkerStatus:
    worker_id: str
    organization_id: int
    active_job: str | None
    heartbeat_at: datetime


class WorkerRegistry:
    def heartbeat(self, db: Session, *, worker_id: str, organization_id: int, active_job: str | None = None) -> WorkerLease:
        now = utcnow()
        lease = db.get(WorkerLease, worker_id)
        if lease is None:
            lease = WorkerLease(worker_id=worker_id, organization_id=organization_id, job_id=active_job, heartbeat_at=now)
            db.add(lease)
        else:
            if lease.organization_id != organization_id:
                raise PermissionError("worker tenant mismatch")
            lease.job_id = active_job
            lease.heartbeat_at = now
        db.commit()
        db.refresh(lease)
        return lease

    def healthy(self, db: Session, *, organization_id: int, timeout_seconds: int = 60) -> list[WorkerLease]:
        cutoff = utcnow() - timedelta(seconds=timeout_seconds)
        return db.execute(
            select(WorkerLease).where(
                WorkerLease.organization_id == organization_id,
                WorkerLease.heartbeat_at >= cutoff,
            )
        ).scalars().all()


class SecretHasher:
    @staticmethod
    def hash(secret: str) -> tuple[str, str]:
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1)
        return salt.hex(), digest.hex()

    @staticmethod
    def verify(secret: str, salt_hex: str, digest_hex: str) -> bool:
        salt = bytes.fromhex(salt_hex)
        digest = hashlib.scrypt(secret.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(digest.hex(), digest_hex)


queue_v31 = PersistentQueue()
workers_v31 = WorkerRegistry()

# Wave 32 transport bridge -------------------------------------------------
def transport_health(backend: str, url: str | None = None) -> dict:
    """Build a transport and return deterministic health metadata."""
    from app.transport_v32 import build_transport
    transport = build_transport(backend, url)
    return {"backend": backend, "status": "configured", "queue": transport.stats("aegisx.scan")}
