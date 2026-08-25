from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit, parse_qsl, urlencode

from app.scanners.web.discovery import extract_discovery
from app.scanners.web.http_client import SafeHTTPClient
from app.scanners.web.passive_rules import analyze_headers


@dataclass
class WebScanResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    assets: list[dict[str, Any]] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


class WebScanner:
    name = "web"

    def __init__(self, max_pages: int = 20, timeout: float = 15.0) -> None:
        self.max_pages = max_pages
        self.client = SafeHTTPClient(timeout=timeout)

    def run(self, target_url: str, profile: str = "standard", auth_headers: dict[str,str] | None = None) -> WebScanResult:
        queue: deque[str] = deque([target_url])
        seen: set[str] = set()
        result = WebScanResult()
        max_pages = {"quick": 5, "standard": 20, "deep": 50, "red-team": 50}.get(profile, 20)
        selected_max = min(self.max_pages, max_pages)

        while queue and len(seen) < selected_max:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                response = self.client.get(url, auth_headers)
            except Exception as exc:
                result.findings.append({
                    "finding_key": "WEB-SCAN-001",
                    "title": "Target could not be fetched",
                    "severity": "info",
                    "confidence": "confirmed",
                    "category": "Scanner",
                    "description": str(exc),
                    "remediation": "Verify the target URL and scanner network connectivity.",
                    "evidence": {"url": url},
                })
                continue

            result.assets.append({
                "url": response.url,
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "elapsed_ms": response.elapsed_ms,
            })
            result.findings.extend(analyze_headers(response.url, dict(response.headers), response.status_code))

            content_type = response.headers.get("content-type", "").lower()
            if "html" in content_type or not content_type:
                urls, forms, scripts = extract_discovery(response.url, response.text)
                result.forms.extend(forms)
                result.scripts.extend(sorted(scripts))
                result.discovered_urls.extend(sorted(urls))
                # Safe GET-only validation: benign canary reflection and verbose error indicators.
                for candidate in sorted(urls):
                    try:
                        parts = urlsplit(candidate)
                        params = parse_qsl(parts.query, keep_blank_values=True)
                        if params:
                            key = params[0][0]
                            canary = "AEGISX_CANARY_7F3A"
                            probe_params = [(k, canary if k == key else v) for k, v in params]
                            probe = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(probe_params), parts.fragment))
                            probe_resp = self.client.get(probe, auth_headers)
                            if canary in probe_resp.text:
                                result.findings.append({
                                    "finding_key": "WEB-XSS-CANARY-001",
                                    "title": "Reflected input canary observed",
                                    "severity": "medium",
                                    "confidence": "potential",
                                    "category": "Input Validation",
                                    "endpoint": probe,
                                    "description": "A benign canary value was reflected in the HTTP response. Reflection alone is not proof of XSS; contextual output encoding and browser execution should be validated.",
                                    "remediation": "Apply context-appropriate output encoding and validate input handling.",
                                    "evidence": {"url": probe, "parameter": key, "payload": canary, "response_snippet": probe_resp.text[:800]},
                                })
                    except Exception:
                        pass
                body_l = response.text.lower()
                if any(marker in body_l for marker in ("traceback (most recent call last)", "stack trace", "whitelabel error page", "sqlstate[", "org.springframework.web", "sequelizedatabaseerror")):
                    result.findings.append({
                        "finding_key": "WEB-ERR-002",
                        "title": "Potential verbose server error disclosure",
                        "severity": "medium",
                        "confidence": "potential",
                        "category": "Error Handling",
                        "endpoint": response.url,
                        "description": "The response body contains a recognizable server-side error signature. This is an indicator for contextual review, not proof of exploitability.",
                        "remediation": "Return generic client-facing errors and keep stack traces server-side.",
                        "evidence": {"url": response.url, "status_code": response.status_code, "response_snippet": response.text[:1200]},
                    })
                if "<title>index of /" in body_l:
                    result.findings.append({
                        "finding_key": "WEB-DIR-001",
                        "title": "Directory listing indicator",
                        "severity": "medium",
                        "confidence": "confirmed",
                        "category": "Configuration",
                        "endpoint": response.url,
                        "description": "The response resembles a directory index and may expose file names or application structure.",
                        "remediation": "Disable directory listing unless explicitly required.",
                        "evidence": {"url": response.url, "status_code": response.status_code},
                    })
                for candidate in urls:
                    if candidate not in seen and urlparse(candidate).scheme in {"http", "https"}:
                        queue.append(candidate)

        result.discovered_urls = sorted(set(result.discovered_urls))
        result.scripts = sorted(set(result.scripts))
        return result
