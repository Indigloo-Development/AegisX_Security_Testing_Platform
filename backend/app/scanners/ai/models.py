from dataclasses import dataclass, field
from typing import Any

@dataclass
class LLMTarget:
    url: str
    method: str = "POST"
    prompt_field: str = "prompt"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] | None = None
    timeout: float = 15.0

@dataclass
class AIProbeResult:
    probe_id: str
    category: str
    prompt: str
    status_code: int | None
    response_excerpt: str
    indicators: list[str]
    severity: str
    confidence: str
    notes: str

@dataclass
class AIScanResult:
    target: str
    probes: list[AIProbeResult]
    findings: list[dict[str, Any]]
    metadata: dict[str, Any]
