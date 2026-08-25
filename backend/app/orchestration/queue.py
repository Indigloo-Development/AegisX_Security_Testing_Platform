from __future__ import annotations
import asyncio
import heapq
from typing import Callable
from .models import ScanJob

class ScanQueue:
    """Priority-aware in-memory queue; replaceable with Redis/RabbitMQ adapter later."""
    def __init__(self) -> None:
        self._items: dict[str, ScanJob] = {}
        self._ready: list[tuple[int,float,str]] = []
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()

    async def enqueue(self, job: ScanJob) -> ScanJob:
        async with self._lock:
            self._items[job.job_id] = job
            heapq.heappush(self._ready, (-int(job.priority), job.created_at, job.job_id))
            self._wake.set()
        return job

    async def get(self) -> ScanJob:
        while True:
            async with self._lock:
                if self._ready:
                    self._wake.clear()
                else:
                    self._wake.clear()
                    waiter=True
                    job=None
                if self._ready:
                    waiter=False
                else:
                    waiter=True
            if waiter:
                await self._wake.wait()
                continue
            # Small dispatch window lets near-simultaneous jobs be priority-ordered.
            await asyncio.sleep(0.005)
            async with self._lock:
                while self._ready:
                    _prio,_created,jid=heapq.heappop(self._ready); job=self._items.get(jid)
                    if job and job.status.value=='queued': return job

    async def cancel(self, job_id: str) -> bool:
        async with self._lock:
            job=self._items.get(job_id)
            if not job: return False
            job.request_cancel(); return True

    async def get_job(self, job_id: str) -> ScanJob|None:
        return self._items.get(job_id)

    async def all(self) -> list[ScanJob]:
        return list(self._items.values())
