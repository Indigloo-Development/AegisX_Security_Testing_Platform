from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    family: str
    prompt: str
    expected_labels: tuple[str, ...]
    expected_safe: bool
    severity_weight: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
