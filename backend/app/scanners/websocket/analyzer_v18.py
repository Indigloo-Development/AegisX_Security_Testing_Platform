from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class WebSocketFinding:
    key: str
    title: str
    severity: str
    confidence: str
    evidence: str
    remediation: str


def analyze_handshake(*, url: str, request_headers: dict[str, str], response_headers: dict[str, str]) -> list[WebSocketFinding]:
    req = {k.lower(): v for k, v in request_headers.items()}
    resp = {k.lower(): v for k, v in response_headers.items()}
    out: list[WebSocketFinding] = []
    origin = req.get("origin", "")
    if resp.get("sec-websocket-accept") and not origin:
        out.append(WebSocketFinding("WS-ORIGIN-001", "WebSocket handshake lacks observable Origin header", "MEDIUM", "LOW", "No Origin header observed in supplied handshake request", "Require and validate an Origin or equivalent application-level authorization control where appropriate."))
    if url.lower().startswith("ws://"):
        out.append(WebSocketFinding("WS-TLS-001", "WebSocket uses unencrypted ws:// transport", "HIGH", "HIGH", "Target URL uses ws://", "Use wss:// with TLS for production authentication/session traffic."))
    if resp.get("access-control-allow-origin") == "*" and origin:
        out.append(WebSocketFinding("WS-CORS-001", "Handshake exposes wildcard CORS header", "LOW", "MEDIUM", "Access-Control-Allow-Origin: * observed", "Review whether the handshake response needs this header and narrow it where applicable."))
    return out


def analyze_message(*, message: str, direction: str = "server-to-client", metadata: dict[str, Any] | None = None) -> list[WebSocketFinding]:
    metadata = metadata or {}
    out: list[WebSocketFinding] = []
    lower = message.lower()
    if "<script" in lower or "javascript:" in lower:
        out.append(WebSocketFinding("WS-OUTPUT-001", "WebSocket message contains active-content marker", "MEDIUM", "MEDIUM", f"{direction} message contains script-like content", "Treat WebSocket message data as untrusted and encode/sanitize before DOM insertion."))
    if metadata.get("auth_required") is False and metadata.get("sensitive_action") is True:
        out.append(WebSocketFinding("WS-AUTHZ-001", "Sensitive WebSocket action lacks declared authorization requirement", "HIGH", "MEDIUM", "Metadata declares sensitive_action=true and auth_required=false", "Require explicit authentication and authorization for sensitive socket actions."))
    return out


def as_dict(findings: list[WebSocketFinding]) -> list[dict]:
    return [asdict(f) for f in findings]
