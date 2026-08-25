from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlparse

import httpx


@dataclass
class HTTPResponse:
    url: str
    status_code: int
    headers: Mapping[str, str]
    text: str
    history: list[int]
    elapsed_ms: float


class SafeHTTPClient:
    """GET-only client for low-impact discovery and passive analysis."""

    def __init__(self, timeout: float = 15.0, user_agent: str = "AegisX-WebScanner/0.1") -> None:
        self.timeout = timeout
        self.user_agent = user_agent

    def _validate_target(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Target must be an absolute HTTP/HTTPS URL")

    def get(self, url: str, extra_headers: Mapping[str,str] | None = None) -> HTTPResponse:
        self._validate_target(url)
        headers = {"User-Agent": self.user_agent, "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
        if extra_headers: headers.update(extra_headers)
        with httpx.Client(timeout=self.timeout, follow_redirects=True, headers=headers) as client:
            response = client.get(url)
            return HTTPResponse(
                url=str(response.url),
                status_code=response.status_code,
                headers=response.headers,
                text=response.text[:2_000_000],
                history=[r.status_code for r in response.history],
                elapsed_ms=response.elapsed.total_seconds() * 1000,
            )
