"""Canonical AegisX worker entrypoint.

Compatibility wrapper for the latest Wave 39 runtime.  It delegates to the
Wave 33 graceful-drain worker so existing commands continue to work:

    python -m app.worker

Configuration is controlled by the same environment variables as worker_v33:
AEGISX_QUEUE_BACKEND, AEGISX_QUEUE_URL, AEGISX_QUEUE_NAME, AEGISX_WORKER_ID.
"""

from __future__ import annotations

from app.worker_v33 import main


if __name__ == "__main__":
    raise SystemExit(main())
