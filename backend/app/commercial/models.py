from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

@dataclass
class AuthProfile:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    bearer_token: str | None = None
    basic_username: str | None = None
    basic_password: str | None = None

    def sanitized(self) -> dict[str, Any]:
        safe_headers = {k: ("***" if k.lower() in {"authorization", "x-api-key", "proxy-authorization"} else v) for k, v in self.headers.items()}
        return {"name": self.name, "headers": safe_headers, "cookies": {k: "***" for k in self.cookies}, "has_bearer_token": bool(self.bearer_token), "has_basic_auth": self.basic_username is not None}

@dataclass
class ScanPolicy:
    max_requests: int = 100
    max_pages: int = 50
    timeout_seconds: float = 15.0
    same_origin_only: bool = True
    follow_redirects: bool = True
    allow_active_safe_checks: bool = True
    allow_state_changing_methods: bool = False

    def validate(self) -> None:
        if not 1 <= self.max_requests <= 10000:
            raise ValueError("max_requests must be between 1 and 10000")
        if not 1 <= self.max_pages <= 1000:
            raise ValueError("max_pages must be between 1 and 1000")
        if not 1 <= self.timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")

@dataclass
class ScanJobResult:
    target: str
    profile: str
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
