from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx


@dataclass
class HTTPResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str


def normalize_base(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute HTTP/HTTPS URL")
    return url.rstrip("/")


def fetch(url: str, *, method: str = "GET", json_body: dict | None = None, timeout: float = 10.0) -> HTTPResult:
    headers = {"User-Agent": "AegisX-API-Scanner/0.3"}
    with httpx.Client(follow_redirects=True, timeout=timeout, headers=headers) as client:
        response = client.request(method, url, json=json_body)
    return HTTPResult(
        url=str(response.url),
        status_code=response.status_code,
        headers={k.lower(): v for k, v in response.headers.items()},
        body=response.text,
        content_type=response.headers.get("content-type", "").lower(),
    )


def joined(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))
