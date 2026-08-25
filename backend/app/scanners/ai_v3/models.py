from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class AttackStep:
    id: str
    category: str
    prompt: str
    purpose: str
    next_on: tuple[str, ...] = ()

@dataclass
class CampaignConfig:
    target_url: str
    provider: str = "generic-json"
    method: str = "POST"
    prompt_field: str = "prompt"
    headers: dict[str, str] = field(default_factory=dict)
    body_template: dict[str, Any] = field(default_factory=dict)
    timeout: float = 15.0
    max_turns: int = 4
    max_steps: int = 8

@dataclass
class StepResult:
    step_id: str
    category: str
    turn: int
    status_code: int | None
    text_excerpt: str
    labels: list[str]
    severity: str
    confidence: str
    next_strategy: str | None

@dataclass
class CampaignResult:
    target: str
    provider: str
    status: str
    steps: list[StepResult]
    findings: list[dict[str, Any]]
    metrics: dict[str, Any]
