import httpx
from .analyzer import analyze_mcp_config, run_agent_campaign
from .models import AgentTarget, AgentResult

class AgentSecurityScanner:
    name = "agent"

    async def run(self, target: AgentTarget) -> AgentResult:
        async with httpx.AsyncClient() as client:
            return await run_agent_campaign(target, client)

    def analyze_mcp(self, config: dict) -> dict:
        return analyze_mcp_config(config)
