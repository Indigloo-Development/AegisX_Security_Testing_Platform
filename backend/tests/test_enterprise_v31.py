from datetime import datetime, timezone, timedelta

from app.db.session import SessionLocal
from app.models.models import Base, DistributedJob
from app.db.session import engine
from app.enterprise_v31 import PersistentQueue, JobState, WorkerRegistry, SecretHasher


def test_persistent_queue_lifecycle():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    q = PersistentQueue()
    job_id = 'wave31-job-1'
    old = db.get(DistributedJob, job_id)
    if old:
        db.delete(old); db.commit()
    job = q.submit(db, job_id=job_id, organization_id=1, payload={'scan':'web'}, priority=90, max_attempts=2)
    assert job.state == 'queued'
    claimed = q.claim(db, worker_id='worker-1', organization_id=1)
    assert claimed and claimed.state == 'running' and claimed.attempts == 1
    q.heartbeat(db, job_id=job_id, worker_id='worker-1')
    retried = q.fail_or_retry(db, job_id=job_id, worker_id='worker-1', error='temporary')
    assert retried.state == 'queued'
    retried.available_at = datetime.now(timezone.utc)
    db.commit()
    claimed2 = q.claim(db, worker_id='worker-2', organization_id=1)
    assert claimed2 and claimed2.attempts == 2
    dead = q.fail_or_retry(db, job_id=job_id, worker_id='worker-2', error='permanent')
    assert dead.state == 'dead_letter'
    db.close()


def test_cancel_and_tenant_isolation():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    q = PersistentQueue()
    job_id = 'wave31-job-2'
    old = db.get(DistributedJob, job_id)
    if old:
        db.delete(old); db.commit()
    q.submit(db, job_id=job_id, organization_id=20, payload={})
    try:
        q.cancel(db, job_id=job_id, organization_id=21)
        assert False
    except KeyError:
        pass
    job = q.cancel(db, job_id=job_id, organization_id=20)
    assert job.state == 'cancelled'
    db.close()


def test_secret_hash_verify():
    salt, digest = SecretHasher.hash('example-secret')
    assert SecretHasher.verify('example-secret', salt, digest)
    assert not SecretHasher.verify('wrong-secret', salt, digest)
