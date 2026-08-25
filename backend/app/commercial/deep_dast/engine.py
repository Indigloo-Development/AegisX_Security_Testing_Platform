from __future__ import annotations
import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import Any
import httpx
from .models import DeepDASTRequest, DeepDASTResult, RetestRequest, RoleProfile

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*error", r"mysql_fetch", r"PostgreSQL.*ERROR", r"ORA-\d{4,}",
    r"SQLite/JDBCDriver", r"Unclosed quotation mark", r"ODBC SQL Server Driver"
]

class DeepAuthenticatedDAST:
    """Safe authenticated DAST orchestration. State-changing methods are never issued."""
    async def _login_storage(self, request: DeepDASTRequest) -> tuple[dict, list[dict]]:
        if not request.auth_workflow:
            return {}, []
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is required for auth workflows") from exc
        wf = request.auth_workflow
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            ctx = await browser.new_context()
            page = await ctx.new_page()
            try:
                await page.goto(str(wf.login_url), wait_until="domcontentloaded", timeout=request.navigation_timeout_ms)
                await page.fill(wf.username_selector, wf.username)
                await page.fill(wf.password_selector, wf.password.get_secret_value())
                await page.click(wf.submit_selector)
                await page.wait_for_load_state("domcontentloaded", timeout=request.navigation_timeout_ms)
                if wf.success_indicator and not await page.locator(wf.success_indicator).count():
                    raise RuntimeError("Login completed but success indicator was not found")
                storage = await ctx.storage_state()
                cookies = storage.get("cookies", [])
                return {}, cookies
            finally:
                await browser.close()

    @staticmethod
    def _normalize(base: str, link: str, origin: str, same_origin: bool) -> str | None:
        full = urljoin(base, link).split("#", 1)[0]
        p = urlparse(full)
        if p.scheme not in {"http", "https"}:
            return None
        if same_origin and p.netloc != origin:
            return None
        return full

    @staticmethod
    def _passive_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
        lower = {k.lower(): v for k, v in headers.items()}
        findings = []
        if "content-security-policy" not in lower:
            findings.append({"type": "missing_csp", "severity": "medium", "confidence": "confirmed"})
        if "strict-transport-security" not in lower:
            findings.append({"type": "missing_hsts", "severity": "medium", "confidence": "confirmed"})
        if lower.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({"type": "missing_nosniff", "severity": "low", "confidence": "confirmed"})
        return findings

    @staticmethod
    def _reflected_canary(text: str) -> bool:
        return "AEGISX_DAST_CANARY_9f3d" in text

    @staticmethod
    def _sql_error(text: str) -> bool:
        return any(re.search(p, text, re.I) for p in SQL_ERROR_PATTERNS)

    async def _crawl(self, client: httpx.AsyncClient, target: str, max_pages: int, same_origin_only: bool):
        origin = urlparse(target).netloc
        queue = [target]
        seen = {target}
        pages = []
        endpoints = set()
        while queue and len(pages) < max_pages:
            url = queue.pop(0)
            try:
                r = await client.get(url, follow_redirects=True)
            except Exception:
                continue
            pages.append((url, r))
            ct = r.headers.get("content-type", "")
            if "text/html" not in ct.lower():
                continue
            for link in re.findall(r'href=["\']([^"\']+)', r.text, re.I):
                u = self._normalize(url, link, origin, same_origin_only)
                if u and u not in seen and len(seen) < max_pages * 5:
                    seen.add(u); queue.append(u)
                    endpoints.add(u)
            for api in re.findall(r'(?:(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*["\'])(/[^"\']+)', r.text, re.I):
                u = self._normalize(url, api, origin, same_origin_only)
                if u:
                    endpoints.add(u)
        return pages, sorted(endpoints)

    async def _role_probe(self, client: httpx.AsyncClient, role: RoleProfile, endpoints: list[str]) -> list[dict]:
        findings = []
        # Safe differential planning: GET only, no writes. Compare status/body-size signals between roles.
        for endpoint in endpoints[:30]:
            try:
                r = await client.get(endpoint, headers=role.headers, cookies={c["name"]: c["value"] for c in role.cookies})
                findings.append({"role": role.name, "url": endpoint, "status": r.status_code, "content_length": len(r.content)})
            except Exception as exc:
                findings.append({"role": role.name, "url": endpoint, "error": str(exc)})
        return findings

    async def scan(self, request: DeepDASTRequest) -> DeepDASTResult:
        headers, cookies = await self._login_storage(request)
        if request.auth_workflow and cookies:
            pass
        async with httpx.AsyncClient(timeout=request.navigation_timeout_ms / 1000, headers=headers, cookies={c["name"]: c["value"] for c in cookies}, follow_redirects=True) as client:
            pages, endpoints = await self._crawl(client, str(request.target_url), request.max_pages, request.same_origin_only)
            findings: list[dict] = []
            for url, response in pages:
                findings.extend([{**f, "url": url} for f in self._passive_headers(dict(response.headers))])
                if request.enable_safe_validators and "text/html" in response.headers.get("content-type", "").lower():
                    if self._reflected_canary(response.text):
                        findings.append({"type": "potential_reflected_input", "severity": "medium", "confidence": "potential", "url": url, "evidence": "AEGISX_DAST_CANARY_9f3d reflected"})
                    if self._sql_error(response.text):
                        findings.append({"type": "database_error_disclosure", "severity": "medium", "confidence": "potential", "url": url})
            role_results = []
            for role in request.roles:
                role_results.extend(await self._role_probe(client, role, endpoints))
            return DeepDASTResult(target_url=str(request.target_url), authenticated=bool(request.auth_workflow), roles_tested=[r.name for r in request.roles], pages_scanned=len(pages), endpoints_discovered=endpoints, findings=findings + [{"type": "role_observation", "severity": "info", "confidence": "observed", "evidence": x} for x in role_results])

    async def retest(self, request: RetestRequest) -> dict:
        url = str(request.test_url or request.target_url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(url, headers=request.headers)
        return {"finding_type": request.finding_type, "url": url, "status": r.status_code, "reproduced": (request.original_status is None or r.status_code == request.original_status)}
