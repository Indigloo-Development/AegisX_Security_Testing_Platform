import asyncio
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class QueueJob:
    id: str
    status: str = "queued"
    result: object = None
    error: str | None = None

class ScanQueue:
    def __init__(self):
        self.jobs: Dict[str, QueueJob] = {}
        self._tasks: Dict[str, asyncio.Task] = {}

    def submit(self, job_id, coroutine):
        job = QueueJob(job_id)
        self.jobs[job_id] = job
        async def runner():
            job.status = "running"
            try:
                job.result = await coroutine
                job.status = "completed"
            except asyncio.CancelledError:
                job.status = "cancelled"
                raise
            except Exception as exc:
                job.status = "failed"
                job.error = str(exc)
        self._tasks[job_id] = asyncio.create_task(runner())
        return job

    def get(self, job_id):
        return self.jobs.get(job_id)

    def cancel(self, job_id):
        task = self._tasks.get(job_id)
        if task and not task.done():
            task.cancel()
            return True
        return False
