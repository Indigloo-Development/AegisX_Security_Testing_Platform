from __future__ import annotations

import re
from typing import Any

from app.scanners.api.common.http import normalize_base

SERVICE_RE = re.compile(r"\bservice\s+(\w+)\s*\{")
RPC_RE = re.compile(r"\brpc\s+(\w+)\s*\([^)]*\)\s+returns\s*\([^)]*\)")


def inventory_proto(proto_text: str) -> dict[str, Any]:
    services = SERVICE_RE.findall(proto_text)
    rpc_methods = RPC_RE.findall(proto_text)
    return {"services": services, "rpc_methods": rpc_methods, "service_count": len(services), "rpc_count": len(rpc_methods)}


def scan_grpc(target_url: str) -> tuple[list[dict[str, Any]], list[dict]]:
    # Full gRPC reflection/HTTP2 invocation is isolated behind this adapter; Phase 3 provides
    # a safe URL inventory and an import-compatible proto parser without issuing arbitrary calls.
    normalize_base(target_url)
    return [{"target": target_url, "mode": "adapter-ready", "note": "gRPC reflection/proto inventory adapter is available; active HTTP/2 method testing is reserved for the authorized deep API profile."}], []
