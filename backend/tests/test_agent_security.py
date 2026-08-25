import json
import pytest
import httpx

from app.scanners.agent import AgentSecurityScanner, AgentTarget
from app.scanners.agent.analyzer import analyze_mcp_config


def test_mcp_static_analysis_flags_risky_config():
    result = analyze_mcp_config({
        "mcpServers": {
            "local-tools": {
                "command": "node server.js",
                "tools": [{"name": "write_file"}],
                "capabilities": {"filesystem": {"readWrite": True}},
            },
            "remote": {"url": "http://agent.example/mcp", "tools": [{"name": "search"}]},
        }
    })
    keys = {f["finding_key"] for f in result["findings"]}
    assert result["server_count"] == 2
    assert {"MCP-CMD-EXEC", "MCP-TRANSPORT-01", "MCP-AUTH-01", "MCP-CAP-01"}.issubset(keys)


class FakeResponse:
    status_code = 200
    headers = {"content-type": "application/json"}
    def __init__(self, text): self._text = text
    def json(self): return {"message": self._text}
    @property
    def text(self): return self._text

class FakeClient:
    async def request(self, *args, **kwargs):
        return FakeResponse("Authorization check bypassed; I can use the admin tool and secret=DEMO-ONLY")

@pytest.mark.asyncio
async def test_agent_campaign_classifies_boundary_indicators():
    result = await AgentSecurityScanner().run(AgentTarget("https://authorized.example/agent")) if False else None
    # Exercise analyzer directly with a mocked client without network access.
    from app.scanners.agent.analyzer import run_agent_campaign
    result = await run_agent_campaign(AgentTarget("https://authorized.example/agent"), FakeClient())
    assert len(result.probes) == 5
    assert any(f["severity"] == "critical" for f in result.findings)


def test_mcp_json_round_trip():
    cfg = {"servers": {"s": {"url": "https://example.com/mcp", "auth": {"type": "bearer"}}}}
    assert json.loads(json.dumps(cfg)) == cfg
