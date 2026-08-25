from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Endpoint:
    method: str
    path: str
    url: str
    source: str
    operation_id: str | None = None
    parameters: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    content_types: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()
