from __future__ import annotations

import os
import signal
import time

from app.transport_v32 import TransportError, build_transport

_running = True


def stop(*_args):
    global _running
    _running = False


def main() -> int:
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    backend = os.getenv("AEGISX_QUEUE_BACKEND", "memory")
    url = os.getenv("AEGISX_QUEUE_URL")
    queue = os.getenv("AEGISX_QUEUE_NAME", "aegisx.scan")
    worker_id = os.getenv("AEGISX_WORKER_ID", f"worker-{os.getpid()}")
    try:
        transport = build_transport(backend, url)
    except TransportError as exc:
        print(f"worker configuration error: {exc}")
        return 2
    print(f"AegisX worker {worker_id} listening on {queue} via {backend}")
    while _running:
        message = transport.consume(queue, timeout=1.0)
        if not message:
            continue
        receipt = message["receipt"]
        try:
            # Scanner execution is intentionally delegated to the orchestrator/worker adapter.
            # This process only proves transport delivery and acknowledgement semantics.
            transport.ack(receipt)
        except Exception:
            transport.nack(receipt, requeue=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
