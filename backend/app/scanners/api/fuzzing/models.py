from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FuzzCase:
    case_id: str
    method: str
    path: str
    parameter: str | None
    location: str | None
    mutation: str
    value: Any
    rationale: str
    safe: bool = True


@dataclass(frozen=True)
class ResponseObservation:
    identity: str
    status: int | None
    content_type: str | None = None
    content_length: int | None = None
    body_fingerprint: str | None = None
    markers: tuple[str, ...] = ()


@dataclass
class FuzzAnalysis:
    cases: list[FuzzCase] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    observations: list[ResponseObservation] = field(default_factory=list)
    workflows: list[dict[str, Any]] = field(default_factory=list)
