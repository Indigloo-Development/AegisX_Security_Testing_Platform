from dataclasses import dataclass, field
from typing import Any

@dataclass
class AgentTarget:
    target_url: str
    method: str = "POST"
    message_field: str = "message"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] = field(default_factory=dict)
    timeout: float = 15.0

@dataclass
class AgentProbe:
    probe_id: str
    category: str
    status_code: int | None
    response_excerpt: str
    indicators: list[str] = field(default_factory=list)
    severity: str = "info"
    confidence: str = "potential"
    notes: str = ""

@dataclass
class MCPConfig:
    config: dict[str, Any]

@dataclass
class AgentResult:
    target: str
    metadata: dict[str, Any]
    probes: list[AgentProbe] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    mcp_analysis: dict[str, Any] = field(default_factory=dict)
