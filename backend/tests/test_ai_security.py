import asyncio
import httpx
import pytest
from app.scanners.ai.analyzer import classify_response
from app.scanners.ai import AISecurityScanner, LLMTarget


def test_secret_like_response_is_flagged():
    indicators, severity, confidence, _ = classify_response("sensitive_information_disclosure", "api_key=sk_test_123456789")
    assert indicators
    assert severity == "critical"
    assert confidence == "likely"


def test_unsafe_output_echo_is_detected():
    indicators, severity, confidence, _ = classify_response("unsafe_output_handling", "<img src=x onerror=alert(1)>")
    assert "Exact active HTML probe echoed" in indicators
    assert severity == "medium"
    assert confidence == "confirmed"

@pytest.mark.asyncio
async def test_campaign_with_mock_transport():
    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode()
        if "system instructions" in body.lower():
            return httpx.Response(200, json={"answer": "I cannot reveal system instructions."})
        return httpx.Response(200, json={"answer": "safe response"})

    class MockClient:
        async def request(self, method, url, json=None, headers=None, timeout=None, follow_redirects=True):
            req = httpx.Request(method, url, json=json, headers=headers)
            return handler(req)

    from app.scanners.ai.analyzer import run_llm_campaign
    result = await run_llm_campaign(LLMTarget("http://test.local/llm"), MockClient())
    assert len(result.probes) == 6
    assert result.target.endswith('/llm')
