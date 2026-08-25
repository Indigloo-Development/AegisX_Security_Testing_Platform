from __future__ import annotations

import os
import signal
import threading
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class WorkerScalingPolicy:
    min_replicas: int = 2
    max_replicas: int = 20
    target_queue_depth: int = 10
    scale_up_step: int = 2
    scale_down_step: int = 1

    @classmethod
    def from_env(cls) -> "WorkerScalingPolicy":
        return cls(
            min_replicas=max(1, int(os.getenv("AEGISX_WORKER_MIN", "2"))),
            max_replicas=max(1, int(os.getenv("AEGISX_WORKER_MAX", "20"))),
            target_queue_depth=max(1, int(os.getenv("AEGISX_WORKER_TARGET_QUEUE", "10"))),
            scale_up_step=max(1, int(os.getenv("AEGISX_WORKER_SCALE_UP_STEP", "2"))),
            scale_down_step=max(1, int(os.getenv("AEGISX_WORKER_SCALE_DOWN_STEP", "1"))),
        )


def desired_replicas(queue_depth: int, current: int, policy: WorkerScalingPolicy) -> int:
    queue_depth = max(0, int(queue_depth))
    current = max(policy.min_replicas, min(policy.max_replicas, int(current)))
    if queue_depth > policy.target_queue_depth:
        return min(policy.max_replicas, current + policy.scale_up_step)
    if queue_depth == 0 and current > policy.min_replicas:
        return max(policy.min_replicas, current - policy.scale_down_step)
    return current


class GracefulDrain:
    def __init__(self) -> None:
        self._draining = threading.Event()

    def request(self) -> None:
        self._draining.set()

    @property
    def is_draining(self) -> bool:
        return self._draining.is_set()


def install_drain_handlers(drain: GracefulDrain) -> None:
    signal.signal(signal.SIGTERM, lambda *_: drain.request())
    signal.signal(signal.SIGINT, lambda *_: drain.request())
