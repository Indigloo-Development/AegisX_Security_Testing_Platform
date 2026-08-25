from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any
import uuid

class JobStatus(str, Enum):
    QUEUED='queued'; RUNNING='running'; PAUSED='paused'; CANCEL_REQUESTED='cancel_requested'; CANCELLED='cancelled'; COMPLETED='completed'; FAILED='failed'

class JobPriority(int, Enum):
    LOW=10; NORMAL=50; HIGH=80; CRITICAL=100

@dataclass(slots=True)
class ScanJob:
    target: str
    scanner: str='web'
    priority: int=JobPriority.NORMAL
    max_retries: int=2
    rate_limit_rps: float=2.0
    job_id: str=field(default_factory=lambda: uuid.uuid4().hex)
    status: JobStatus=JobStatus.QUEUED
    attempts: int=0
    created_at: float=field(default_factory=time)
    started_at: float|None=None
    finished_at: float|None=None
    error: str|None=None
    result: dict[str, Any]|None=None
    progress: int=0
    cancel_requested: bool=False

    def request_cancel(self) -> None:
        self.cancel_requested=True
        if self.status in {JobStatus.QUEUED, JobStatus.RUNNING, JobStatus.PAUSED}:
            self.status=JobStatus.CANCEL_REQUESTED
