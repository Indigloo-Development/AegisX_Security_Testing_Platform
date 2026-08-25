import asyncio
import pytest
from app.orchestration import ScanQueue, ScanScheduler, ScanJob, JobStatus, TokenBucket

@pytest.mark.asyncio
async def test_priority_queue_and_worker_completion():
    q=ScanQueue(); scheduler=ScanScheduler(q, concurrency=1)
    seen=[]
    async def runner(job):
        seen.append(job.scanner); return {'ok':True}
    await scheduler.start(runner)
    low=ScanJob('https://low', scanner='low', priority=10)
    high=ScanJob('https://high', scanner='high', priority=90)
    await q.enqueue(low); await q.enqueue(high)
    for _ in range(100):
        if high.status==JobStatus.COMPLETED and low.status==JobStatus.COMPLETED: break
        await asyncio.sleep(0.01)
    assert seen[0]=='high'
    assert low.status==JobStatus.COMPLETED
    await scheduler.shutdown()

@pytest.mark.asyncio
async def test_cancel_queued_job():
    q=ScanQueue(); job=ScanJob('https://example', priority=50)
    await q.enqueue(job); assert await q.cancel(job.job_id)
    assert job.status==JobStatus.CANCEL_REQUESTED

@pytest.mark.asyncio
async def test_retry_then_fail():
    q=ScanQueue(); scheduler=ScanScheduler(q, concurrency=1); calls=0
    async def runner(job):
        nonlocal calls; calls+=1; raise RuntimeError('boom')
    await scheduler.start(runner)
    job=ScanJob('https://example', max_retries=1); await q.enqueue(job)
    for _ in range(200):
        if job.status==JobStatus.FAILED: break
        await asyncio.sleep(0.02)
    assert calls==2 and job.status==JobStatus.FAILED
    await scheduler.shutdown()

@pytest.mark.asyncio
async def test_token_bucket_rate_limiter():
    bucket=TokenBucket(100)
    await bucket.acquire(); await bucket.acquire()
