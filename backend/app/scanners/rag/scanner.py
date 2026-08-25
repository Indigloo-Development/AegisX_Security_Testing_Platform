import httpx
from .analyzer import run_rag_campaign
from .models import RAGTarget


class RAGSecurityScanner:
    name = "rag"

    async def run(self, target: RAGTarget):
        async with httpx.AsyncClient(follow_redirects=True) as client:
            return await run_rag_campaign(target, client)
