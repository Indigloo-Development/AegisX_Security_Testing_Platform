from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class ProtocolIssue:
    key: str
    severity: str
    confidence: str
    title: str
    evidence: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

class GraphQLValidator:
    """Safe schema/configuration validator; does not execute attacker queries."""
    def analyze(self, schema: dict[str, Any]) -> list[ProtocolIssue]:
        issues: list[ProtocolIssue] = []
        query = schema.get("query") or {}
        mutation = schema.get("mutation") or {}
        metadata = schema.get("metadata") or {}
        if metadata.get("introspection_public") is True:
            issues.append(ProtocolIssue("GQL-001", "medium", "confirmed", "Public GraphQL introspection", "metadata.introspection_public=true", "Restrict introspection in production or trusted environments."))
        if metadata.get("depth_limit") is None:
            issues.append(ProtocolIssue("GQL-002", "medium", "potential", "Missing query depth limit", "metadata.depth_limit is absent", "Enforce a maximum query depth."))
        if metadata.get("complexity_limit") is None:
            issues.append(ProtocolIssue("GQL-003", "medium", "potential", "Missing query complexity limit", "metadata.complexity_limit is absent", "Enforce query-cost/complexity budgets."))
        if metadata.get("alias_limit") is None:
            issues.append(ProtocolIssue("GQL-004", "low", "potential", "Missing alias/batching limit", "metadata.alias_limit is absent", "Bound aliases, batching and request fan-out."))
        for name, op in query.items() if isinstance(query, dict) else []:
            if isinstance(op, dict) and op.get("authorization") is False:
                issues.append(ProtocolIssue("GQL-005", "high", "confirmed", "Query resolver lacks authorization", f"query.{name}.authorization=false", "Enforce resolver-level authorization."))
        for name, op in mutation.items() if isinstance(mutation, dict) else []:
            if isinstance(op, dict) and op.get("authorization") is False:
                issues.append(ProtocolIssue("GQL-006", "critical", "confirmed", "Mutation resolver lacks authorization", f"mutation.{name}.authorization=false", "Require explicit authorization for state-changing resolvers."))
        return issues
