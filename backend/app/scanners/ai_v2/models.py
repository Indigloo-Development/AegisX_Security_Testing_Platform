from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class LLMProvider:
    name: str
    request_style: str
    default_content_type: str = 'application/json'

PROVIDERS = {
    'openai-compatible': LLMProvider('openai-compatible','chat_completions'),
    'anthropic-compatible': LLMProvider('anthropic-compatible','messages'),
    'gemini-compatible': LLMProvider('gemini-compatible','generate_content'),
    'generic-json': LLMProvider('generic-json','generic'),
}

@dataclass(frozen=True)
class AIProbeSpec:
    id: str
    category: str
    prompt: str
    turn: int
    purpose: str

@dataclass
class CampaignRequest:
    target_url: str
    provider: str = 'generic-json'
    method: str = 'POST'
    prompt_field: str = 'prompt'
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] = field(default_factory=dict)
    timeout: float = 15.0
    max_turns: int = 2

@dataclass
class ProbeObservation:
    probe_id: str
    category: str
    turn: int
    status_code: int | None
    response_excerpt: str
    indicators: list[str]
    severity: str
    confidence: str
    notes: str

@dataclass
class CampaignResult:
    target: str
    provider: str
    observations: list[ProbeObservation]
    findings: list[dict[str, Any]]
    metadata: dict[str, Any]

@dataclass
class RetestRequest:
    target_url: str
    provider: str = 'generic-json'
    prompt_field: str = 'prompt'
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] = field(default_factory=dict)
    original_finding: dict[str, Any] = field(default_factory=dict)
    timeout: float = 15.0
