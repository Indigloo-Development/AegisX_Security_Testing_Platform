from dataclasses import dataclass, field
from typing import Any


@dataclass
class RAGTarget:
    target_url: str
    method: str = "POST"
    query_field: str = "query"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] = field(default_factory=dict)
    timeout: float = 15.0
    tenant_a_header: str | None = None
    tenant_b_header: str | None = None


@dataclass
class RAGProbe:
    probe_id: str
    category: str
    status: str
    request_excerpt: str
    response_excerpt: str
    indicators: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class RAGResult:
    target: str
    metadata: dict[str, Any]
    probes: list[RAGProbe] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
