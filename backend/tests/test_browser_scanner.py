import asyncio

from app.commercial.browser.engine import BrowserScanner
from app.commercial.browser.models import BrowserScanRequest
from app.commercial.browser.queue import ScanQueue


def test_browser_request_defaults():
    req = BrowserScanRequest(target_url="https://example.com")
    assert req.max_pages == 20
    assert req.max_concurrency == 3
    assert req.same_origin_only is True


def test_link_normalization():
    f = BrowserScanner._normalize_link
    assert f("https://example.com/a", "/b#x", "example.com", True) == "https://example.com/b"
    assert f("https://example.com/a", "https://evil.example/b", "example.com", True) is None
    assert f("https://example.com/a", "mailto:test@example.com", "example.com", True) is None


def test_queue_lifecycle():
    async def run():
        q = ScanQueue()
        job = q.submit("j1", asyncio.sleep(0, result={"ok": True}))
        await q._tasks["j1"]
        assert q.get("j1").status == "completed"
        assert q.get("j1").result == {"ok": True}
    asyncio.run(run())
