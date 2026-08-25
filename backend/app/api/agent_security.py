from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from app.api.deps import get_local_operator
from app.scanners.agent import AgentSecurityScanner, AgentTarget

router = APIRouter(prefix="/api/agent-security", tags=["agent-security"])

class AgentScanRequest(BaseModel):
    target_url: HttpUrl
    message_field: str = Field(default="message", min_length=1, max_length=80)
    method: str = Field(default="POST", pattern="^(POST|PUT|PATCH)$")
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict = Field(default_factory=dict)
    timeout: float = Field(default=15.0, ge=2, le=30)

class MCPAnalyzeRequest(BaseModel):
    config: dict

@router.post("/scan")
async def agent_scan(req: AgentScanRequest, _=Depends(get_local_operator)):
    if req.target_url.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS targets are supported")
    target = AgentTarget(str(req.target_url), req.method, req.message_field, req.headers, req.body_template, req.timeout)
    result = await AgentSecurityScanner().run(target)
    return {
        "target": result.target,
        "metadata": result.metadata,
        "probes": [p.__dict__ for p in result.probes],
        "findings": result.findings,
        "disclaimer": "Run only against systems you are authorized to assess. Agent findings require application-context validation. No tool is invoked by the MCP static analyzer.",
    }

@router.post("/mcp/analyze")
def mcp_analyze(req: MCPAnalyzeRequest, _=Depends(get_local_operator)):
    return AgentSecurityScanner().analyze_mcp(req.config)
