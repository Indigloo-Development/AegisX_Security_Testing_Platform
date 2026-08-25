from __future__ import annotations

import os
import signal
import time

from app.scaling_v33 import GracefulDrain, install_drain_handlers
from app.transport_v32 import TransportError, build_transport


def main() -> int:
    drain = GracefulDrain()
    install_drain_handlers(drain)
    backend = os.getenv("AEGISX_QUEUE_BACKEND", "redis")
    url = os.getenv("AEGISX_QUEUE_URL")
    queue = os.getenv("AEGISX_QUEUE_NAME", "aegisx.scan")
    worker_id = os.getenv("AEGISX_WORKER_ID", f"worker-{os.getpid()}")
    try:
        transport = build_transport(backend, url)
    except TransportError as exc:
        print(f"worker configuration error: {exc}")
        return 2
    print(f"AegisX worker {worker_id} listening on {queue} via {backend}")
    while not drain.is_draining:
        message = transport.consume(queue, timeout=1.0)
        if not message:
            continue
        receipt = message["receipt"]
        try:
            transport.ack(receipt)
        except Exception:
            transport.nack(receipt, requeue=True)
    time.sleep(0.1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
