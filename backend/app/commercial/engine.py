from __future__ import annotations
from dataclasses import asdict
from typing import Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import AuthProfile, ScanPolicy
from .auth_context import build_auth_headers, build_cookies
from .risk import score_finding
from .sarif import to_sarif
from .web_active import safe_active_probe

class CommercialEngine:
    """Orchestrates bounded, authorized security analyses without executing arbitrary tools."""
    def __init__(self, policy: ScanPolicy | None = None):
        self.policy = policy or ScanPolicy()
        self.policy.validate()

    def scan_web_active(self, url: str, auth: AuthProfile | None = None) -> dict[str, Any]:
        # Auth profile is exposed for future browser/session-backed probes; GET-only probe uses no state-changing actions.
        findings = safe_active_probe(url, timeout=self.policy.timeout_seconds) if self.policy.allow_active_safe_checks else []
        findings = [{**f, "risk": score_finding(f)} for f in findings]
        return {"target": url, "profile": "commercial-safe-active", "auth_profile": auth.sanitized() if auth else None, "findings": findings, "sarif": to_sarif(findings)}

    def batch_web(self, urls: list[str]) -> dict[str, Any]:
        urls = [u for u in urls if u][:100]
        results: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=min(8, max(1, len(urls)))) as pool:
            futures = {pool.submit(self.scan_web_active, u): u for u in urls}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({"target": futures[future], "profile": "commercial-safe-active", "error": str(exc), "findings": []})
        return {"count": len(results), "results": results}
