from __future__ import annotations
import asyncio
from time import monotonic
from collections.abc import Awaitable, Callable
from typing import Any
from .models import ScanJob, JobStatus
from .queue import ScanQueue

Runner = Callable[[ScanJob], Awaitable[dict[str, Any]]]

class ScanScheduler:
    def __init__(self, queue: ScanQueue, concurrency: int=2) -> None:
        self.queue=queue; self.concurrency=max(1, concurrency); self._tasks:list[asyncio.Task]=[]; self._started=False

    async def start(self, runner: Runner) -> None:
        if self._started: return
        self._started=True
        self._tasks=[asyncio.create_task(self._worker(runner), name=f'aegisx-worker-{i}') for i in range(self.concurrency)]

    async def shutdown(self) -> None:
        for task in self._tasks: task.cancel()
        if self._tasks: await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks=[]; self._started=False

    async def _worker(self, runner: Runner) -> None:
        while True:
            job=await self.queue.get()
            if job.cancel_requested:
                job.status=JobStatus.CANCELLED; job.finished_at=monotonic(); continue
            job.status=JobStatus.RUNNING; job.started_at=monotonic(); job.attempts+=1
            try:
                job.result=await runner(job)
                if job.cancel_requested or job.status==JobStatus.CANCEL_REQUESTED:
                    job.status=JobStatus.CANCELLED
                else:
                    job.progress=100; job.status=JobStatus.COMPLETED
                job.finished_at=monotonic()
            except asyncio.CancelledError:
                job.status=JobStatus.CANCELLED; job.finished_at=monotonic(); raise
            except Exception as exc:
                job.error=str(exc)
                if job.attempts <= job.max_retries and not job.cancel_requested:
                    job.status=JobStatus.QUEUED
                    await asyncio.sleep(min(2 ** (job.attempts-1), 8))
                    await self.queue.enqueue(job)
                else:
                    job.status=JobStatus.FAILED; job.finished_at=monotonic()

class TokenBucket:
    def __init__(self, rate_per_sec: float) -> None:
        self.rate=max(0.1, float(rate_per_sec)); self.tokens=1.0; self.updated=monotonic(); self._lock=asyncio.Lock()
    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now=monotonic(); self.tokens=min(1.0, self.tokens+(now-self.updated)*self.rate); self.updated=now
                if self.tokens>=1.0: self.tokens-=1.0; return
                await asyncio.sleep((1.0-self.tokens)/self.rate)
