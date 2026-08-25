from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from app.commercial.auth_context import build_auth_headers, build_cookies
from app.commercial.models import AuthProfile, ScanPolicy
from app.scanners.web.discovery import extract_discovery
from app.scanners.web.passive_rules import analyze_headers
from app.scanners.web.advanced.analyzers import analyze_page
from app.scanners.web.advanced.discovery import discover_parameters, discover_api_routes, fingerprint_technologies, discover_security_artifacts

@dataclass
class AuthenticatedWebResult:
    target: str
    status: str
    pages: int = 0
    requests: int = 0
    discovered_urls: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    api_routes: list[str] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

class AuthenticatedWebScanner:
    """Bounded, authorized GET-based authenticated web DAST.

    Auth is supplied explicitly by the caller. No credential acquisition or login bypass is attempted.
    Active probes only mutate URL query parameters and never submit forms or state-changing methods.
    """
    def __init__(self, policy: ScanPolicy, auth: AuthProfile | None = None):
        policy.validate()
        self.policy = policy
        self.auth = auth

    @staticmethod
    def _same_origin(seed: str, candidate: str) -> bool:
        a, b = urlparse(seed), urlparse(candidate)
        return (a.scheme, a.netloc) == (b.scheme, b.netloc)

    @staticmethod
    def _with_canary(url: str, parameter: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        out: list[tuple[str, str]] = []
        for k, v in params:
            if k == parameter and not replaced:
                out.append((k, value)); replaced = True
            else:
                out.append((k, v))
        if not replaced:
            out.append((parameter, value))
        return urlunparse(parsed._replace(query=urlencode(out, doseq=True)))

    def run(self, target_url: str, profile: str = "deep") -> AuthenticatedWebResult:
        queue: deque[str] = deque([target_url])
        seen: set[str] = set()
        discovered: set[str] = set()
        scripts: set[str] = set()
        forms: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        parameters: list[dict[str, Any]] = []
        api_routes: set[str] = set()
        technologies: list[dict[str, Any]] = []
        artifacts: set[str] = set()

        headers = {"User-Agent": "AegisX-Commercial-DAST/1.0", "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"}
        headers.update(build_auth_headers(self.auth))
        cookies = build_cookies(self.auth)
        limits = {"quick": 10, "standard": 30, "deep": 75, "red-team": 100}
        max_pages = min(self.policy.max_pages, limits.get(profile, 30))

        with httpx.Client(timeout=self.policy.timeout_seconds, follow_redirects=self.policy.follow_redirects, headers=headers, cookies=cookies) as client:
            while queue and len(seen) < max_pages and len(seen) < self.policy.max_requests:
                url = queue.popleft()
                if url in seen or not self._same_origin(target_url, url):
                    continue
                seen.add(url)
                try:
                    response = client.get(url)
                except Exception as exc:
                    findings.append({
                        "finding_key": "DAST-NET-001", "title": "Target request failed", "severity": "info", "confidence": "confirmed",
                        "category": "Scanner", "description": str(exc), "remediation": "Verify target reachability and scanner connectivity.", "evidence": {"url": url}
                    })
                    continue

                page_ctx = __import__("app.scanners.web.advanced.models", fromlist=["PageContext"]).PageContext(
                    url=str(response.url), status_code=response.status_code, headers=dict(response.headers),
                    body=response.text[:2_000_000], content_type=response.headers.get("content-type", ""), final_url=str(response.url)
                )
                findings.extend(analyze_headers(str(response.url), dict(response.headers), response.status_code))
                findings.extend(analyze_page(page_ctx))
                technologies.extend(fingerprint_technologies(str(response.url), dict(response.headers), response.text))
                parameters.extend(discover_parameters(str(response.url), response.text))
                api_routes.update(discover_api_routes(str(response.url), response.text))
                artifacts.update(discover_security_artifacts(str(response.url), response.text))
                content_type = response.headers.get("content-type", "").lower()
                text = response.text[:2_000_000]
                if "html" in content_type or not content_type:
                    urls, page_forms, page_scripts = extract_discovery(str(response.url), text)
                    forms.extend(page_forms)
                    scripts.update(page_scripts)
                    for candidate in urls:
                        if self._same_origin(target_url, candidate):
                            discovered.add(candidate)
                            if candidate not in seen and len(seen) + len(queue) < self.policy.max_requests:
                                queue.append(candidate)

                    for form in page_forms:
                        action = form.get("action", "")
                        if action.startswith("http://") and any("password" in str(k).lower() for k in form.get("inputs", [])):
                            findings.append({
                                "finding_key": "DAST-FORM-001", "title": "Password form action uses HTTP", "severity": "high", "confidence": "confirmed",
                                "category": "Transport Security", "description": "A discovered password-bearing form submits to an HTTP action.",
                                "remediation": "Submit credentials only over HTTPS.", "evidence": {"page": str(response.url), "action": action}
                            })

                # Safe reflected-input canary on existing query parameters only.
                if self.policy.allow_active_safe_checks:
                    params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
                    for parameter in list(dict.fromkeys(params))[:5]:
                        if len(seen) + 1 >= self.policy.max_requests:
                            break
                        canary = "AegisXCanary_9c7f2"
                        probe_url = self._with_canary(url, parameter, canary)
                        try:
                            probe = client.get(probe_url)
                            if canary in probe.text[:2_000_000]:
                                findings.append({
                                    "finding_key": "DAST-INPUT-001", "title": "User-controlled input reflected in response", "severity": "medium", "confidence": "potential",
                                    "category": "Injection Surface", "description": "A benign scanner canary supplied in a URL parameter was reflected in the response body. Reflection alone does not prove XSS.",
                                    "remediation": "Contextually encode untrusted data and apply an appropriate CSP; validate output in the affected rendering context.",
                                    "evidence": {"url": probe_url, "parameter": parameter, "canary": canary}
                                })
                        except Exception:
                            pass

        return AuthenticatedWebResult(
            target=target_url, status="completed", pages=len(seen), requests=len(seen),
            discovered_urls=sorted(discovered), forms=forms, scripts=sorted(scripts),
            parameters=sorted({(p.get("name"), p.get("location"), p.get("source")): p for p in parameters}.values(), key=lambda x: (x.get("location", ""), x.get("name", ""))),
            api_routes=sorted(api_routes), technologies=sorted({(t.get("name"), t.get("url")): t for t in technologies}.values(), key=lambda x: (x.get("name", ""), x.get("url", ""))),
            artifacts=sorted(artifacts), findings=findings,
        )
