import httpx
from .models import LLMTarget
from .analyzer import run_llm_campaign

class AISecurityScanner:
    name = "ai"

    async def run(self, target: LLMTarget):
        async with httpx.AsyncClient() as client:
            return await run_llm_campaign(target, client)
