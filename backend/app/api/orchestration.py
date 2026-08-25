from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import asyncio
from app.orchestration import ScanQueue, ScanScheduler, ScanJob, JobPriority

router=APIRouter(prefix='/api/orchestration', tags=['Scan Orchestration'])
queue=ScanQueue(); scheduler=ScanScheduler(queue, concurrency=2)
_started=False

class JobRequest(BaseModel):
    target: str
    scanner: str='web'
    priority: int=Field(default=50, ge=10, le=100)
    max_retries: int=Field(default=2, ge=0, le=5)
    rate_limit_rps: float=Field(default=2.0, gt=0, le=100)

async def runner(job: ScanJob):
    # Integration boundary: concrete scanner workers can be registered by scanner name.
    await asyncio.sleep(0)
    return {'target':job.target,'scanner':job.scanner,'worker':'orchestration-stub','rate_limit_rps':job.rate_limit_rps}

async def ensure_started():
    global _started
    if not _started:
        await scheduler.start(runner); _started=True

@router.post('/jobs')
async def create_job(req: JobRequest):
    await ensure_started()
    job=ScanJob(target=req.target,scanner=req.scanner,priority=req.priority,max_retries=req.max_retries,rate_limit_rps=req.rate_limit_rps)
    await queue.enqueue(job)
    return {'job_id':job.job_id,'status':job.status,'priority':job.priority}

@router.get('/jobs/{job_id}')
async def get_job(job_id: str):
    job=await queue.get_job(job_id)
    if not job: raise HTTPException(status_code=404, detail='Job not found')
    return {'job_id':job.job_id,'status':job.status,'attempts':job.attempts,'progress':job.progress,'error':job.error,'result':job.result}

@router.post('/jobs/{job_id}/cancel')
async def cancel_job(job_id: str):
    if not await queue.cancel(job_id): raise HTTPException(status_code=404, detail='Job not found')
    job=await queue.get_job(job_id)
    return {'job_id':job_id,'status':job.status}

@router.get('/workers')
async def worker_health():
    tasks=[not t.done() for t in scheduler._tasks]
    return {'configured_workers':scheduler.concurrency,'active_workers':sum(tasks),'started':_started}
