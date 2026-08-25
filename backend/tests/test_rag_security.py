import asyncio
import json
from app.scanners.rag.analyzer import _indicators, run_rag_campaign
from app.scanners.rag.models import RAGTarget


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    def __init__(self, text):
        self.text = text
    def json(self):
        return {"answer": self.text}


class FakeClient:
    async def request(self, method, url, **kwargs):
        prompt = kwargs["json"]["query"]
        if "metadata" in prompt:
            return FakeResponse("document_id=doc-7 collection=private_embeddings")
        if "tenant" in prompt.lower():
            return FakeResponse("No response from another tenant was provided.")
        return FakeResponse("Safe answer. Retrieved text is treated as data only.")


def test_indicator_detection():
    found = _indicators("document_id=123 collection=private and secret api_key")
    assert "retrieval_metadata" in found
    assert "secret_like" in found


def test_rag_campaign():
    result = asyncio.run(run_rag_campaign(RAGTarget("https://example.test/rag"), FakeClient()))
    assert len(result.probes) == 4
    assert any(f["finding_key"] == "RAG-META-01" for f in result.findings)
