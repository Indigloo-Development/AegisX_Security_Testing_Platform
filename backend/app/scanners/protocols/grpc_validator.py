from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re

@dataclass(frozen=True)
class ProtocolIssue:
    key: str
    severity: str
    confidence: str
    title: str
    evidence: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

class GRPCValidator:
    def analyze(self, proto: str, metadata: dict[str, Any] | None = None) -> list[ProtocolIssue]:
        metadata = metadata or {}
        issues: list[ProtocolIssue] = []
        if metadata.get("plaintext_transport") is True:
            issues.append(ProtocolIssue("GRPC-001", "high", "confirmed", "gRPC plaintext transport", "metadata.plaintext_transport=true", "Use TLS for production gRPC."))
        if metadata.get("reflection_public") is True:
            issues.append(ProtocolIssue("GRPC-002", "medium", "confirmed", "Public gRPC reflection", "metadata.reflection_public=true", "Restrict reflection to trusted environments."))
        services = len(re.findall(r"\bservice\s+[A-Za-z_]\w*\s*\{", proto))
        methods = len(re.findall(r"\brpc\s+[A-Za-z_]\w*\s*\(", proto))
        if services == 0:
            issues.append(ProtocolIssue("GRPC-003", "low", "confirmed", "No gRPC service declaration found", "No service block detected", "Confirm the uploaded .proto is the intended service contract."))
        if methods == 0 and services > 0:
            issues.append(ProtocolIssue("GRPC-004", "low", "potential", "Service contains no detectable RPC methods", "No rpc declaration detected", "Review the service contract and generated bindings."))
        if metadata.get("auth_required") is False:
            issues.append(ProtocolIssue("GRPC-005", "high", "confirmed", "gRPC service does not require authentication", "metadata.auth_required=false", "Require authentication and authorization at the RPC boundary."))
        return issues
