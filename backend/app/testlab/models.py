from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class LabFixture:
    fixture_id: str
    title: str
    category: str
    protocol: str
    expected_rules: tuple[str, ...] = ()
    forbidden_rules: tuple[str, ...] = ()
    context: dict[str, Any] = field(default_factory=dict)
    negative: bool = False

@dataclass(frozen=True)
class FixtureResult:
    fixture_id: str
    passed: bool
    expected: tuple[str, ...]
    detected: tuple[str, ...]
    unexpected: tuple[str, ...]
    missing: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_id": self.fixture_id,
            "passed": self.passed,
            "expected": list(self.expected),
            "detected": list(self.detected),
            "unexpected": list(self.unexpected),
            "missing": list(self.missing),
        }
