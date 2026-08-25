import asyncio
import os
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse
from .models import BrowserScanRequest, BrowserScanResult, BrowserPageEvidence

class BrowserScanner:
    def __init__(self):
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    async def scan(self, request: BrowserScanRequest, resume_urls=None) -> BrowserScanResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError("Playwright is not installed") from exc

        target = str(request.target_url)
        origin = urlparse(target).netloc
        queue = deque(resume_urls or [target])
        seen = set(queue)
        pages = []
        requests_captured = 0
        semaphore = asyncio.Semaphore(request.max_concurrency)

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context_kwargs = {}
            if request.auth.storage_state_path and os.path.isfile(request.auth.storage_state_path):
                context_kwargs["storage_state"] = request.auth.storage_state_path
            context = await browser.new_context(**context_kwargs)
            if request.auth.headers:
                await context.set_extra_http_headers(request.auth.headers)
            if request.auth.cookies:
                await context.add_cookies(request.auth.cookies)

            async def visit(url: str):
                nonlocal requests_captured
                async with semaphore:
                    page = await context.new_page()
                    captured = []
                    page.on("request", lambda req: captured.append(req.url))
                    try:
                        response = await page.goto(url, wait_until="domcontentloaded", timeout=request.navigation_timeout_ms)
                        requests_captured += len(captured)
                        title = await page.title()
                        links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href).slice(0, 100)")
                        scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
                        forms = await page.eval_on_selector_all("form", "els => els.map(e => e.action || location.href)")
                        if request.capture_screenshots:
                            evidence_dir = Path("artifacts/browser")
                            evidence_dir.mkdir(parents=True, exist_ok=True)
                            safe = str(abs(hash(url)))
                            path = evidence_dir / f"{safe}.png"
                            await page.screenshot(path=str(path), full_page=True)
                            screenshot = str(path)
                        else:
                            screenshot = None
                        api_requests = [x for x in captured if "/api/" in x or "graphql" in x.lower()]
                        return BrowserPageEvidence(url=url, status=response.status if response else None, title=title, links=links[:100], scripts=scripts[:100], forms=forms[:100], api_requests=api_requests[:100], screenshot_path=screenshot), [self._normalize_link(url, x, origin, request.same_origin_only) for x in links]
                    finally:
                        await page.close()

            while queue and len(pages) < request.max_pages and not self._cancelled:
                batch = []
                while queue and len(batch) < request.max_concurrency and len(pages) + len(batch) < request.max_pages:
                    batch.append(queue.popleft())
                results = await asyncio.gather(*(visit(u) for u in batch), return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        continue
                    evidence, discovered = result
                    pages.append(evidence)
                    for u in discovered:
                        if u and u not in seen and len(seen) < request.max_pages * 5:
                            seen.add(u); queue.append(u)
            await context.close()
            await browser.close()
        return BrowserScanResult(target_url=target, pages_scanned=len(pages), requests_captured=requests_captured, discovered_urls=list(seen), pages=pages, cancelled=self._cancelled)

    @staticmethod
    def _normalize_link(base, link, origin, same_origin):
        try:
            full = urljoin(base, link)
            parsed = urlparse(full)
            if parsed.scheme not in {"http", "https"}:
                return None
            if same_origin and parsed.netloc != origin:
                return None
            return full.split("#", 1)[0]
        except Exception:
            return None
