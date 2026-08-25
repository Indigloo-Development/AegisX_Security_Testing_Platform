from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from app.api.deps import get_local_operator
from app.scanners.ai_v3 import CampaignConfig, run_adaptive_campaign, analyze_rag_access, evaluate_agent_tool_graph

router=APIRouter(prefix="/api/ai-security-v3", tags=["ai-security-v3"])

class CampaignBody(BaseModel):
    target_url: HttpUrl
    provider: str="generic-json"
    method: str=Field("POST", pattern="^(POST|PUT|PATCH)$")
    prompt_field: str=Field("prompt", min_length=1, max_length=80)
    headers: dict[str,str]=Field(default_factory=dict)
    body_template: dict=Field(default_factory=dict)
    timeout: float=Field(15.0, ge=2, le=30)
    max_turns: int=Field(4, ge=1, le=4)
    max_steps: int=Field(8, ge=1, le=8)

class RAGAccessBody(BaseModel):
    records: list[dict]=Field(default_factory=list, max_length=500)

class AgentGraphBody(BaseModel):
    tools: list[dict]=Field(default_factory=list, max_length=300)

@router.get("/capabilities")
def capabilities(_=Depends(get_local_operator)):
    return {"mode":"bounded-adaptive-defensive","providers":["openai-compatible","anthropic-compatible","gemini-compatible","generic-json"],"features":["multi-turn","adaptive-selection","evidence","retest-ready","rag-authorization","agent-tool-graph"]}

@router.post("/campaign")
async def campaign(body: CampaignBody, _=Depends(get_local_operator)):
    cfg=CampaignConfig(str(body.target_url), body.provider, body.method, body.prompt_field, body.headers, body.body_template, body.timeout, body.max_turns, body.max_steps)
    try:
        result=await run_adaptive_campaign(cfg)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"target":result.target,"provider":result.provider,"status":result.status,"metrics":result.metrics,"steps":[s.__dict__ for s in result.steps],"findings":result.findings,"disclaimer":"Authorized, bounded defensive testing only."}

@router.post("/rag/access")
def rag_access(body:RAGAccessBody,_=Depends(get_local_operator)):
    return analyze_rag_access(body.records)

@router.post("/agent/tool-graph")
def agent_graph(body:AgentGraphBody,_=Depends(get_local_operator)):
    return evaluate_agent_tool_graph(body.tools)
