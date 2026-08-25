from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from app.api.deps import get_local_operator
from app.scanners.ai_v2 import CampaignRequest, RetestRequest, run_campaign, run_retest, analyze_rag_fixture, evaluate_agent_policy, provider_for

router=APIRouter(prefix='/api/ai-security-v2',tags=['ai-security-v2'])

class CampaignBody(BaseModel):
    target_url: HttpUrl
    provider: str='generic-json'
    method: str=Field(default='POST',pattern='^(POST|PUT|PATCH)$')
    prompt_field: str=Field(default='prompt',min_length=1,max_length=80)
    headers: dict[str,str]=Field(default_factory=dict)
    body_template: dict=Field(default_factory=dict)
    timeout: float=Field(default=15.0,ge=2,le=30)
    max_turns: int=Field(default=2,ge=1,le=3)

class RetestBody(BaseModel):
    target_url: HttpUrl
    provider: str='generic-json'
    prompt_field: str='prompt'
    headers: dict[str,str]=Field(default_factory=dict)
    body_template: dict={}
    original_finding: dict={}
    timeout: float=Field(default=15.0,ge=2,le=30)

class RAGFixtureBody(BaseModel):
    documents: list[dict]=Field(default_factory=list,max_length=200)

class AgentPolicyBody(BaseModel):
    tools: list[dict]=Field(default_factory=list,max_length=200)
    allowed_actions: list[str]=Field(default_factory=list,max_length=100)

@router.get('/providers')
def providers(_=Depends(get_local_operator)):
    return {'providers':['openai-compatible','anthropic-compatible','gemini-compatible','generic-json']}

@router.post('/campaign')
async def campaign(body: CampaignBody,_=Depends(get_local_operator)):
    try: provider_for(body.provider)
    except ValueError as exc: raise HTTPException(400,str(exc))
    result=await run_campaign(CampaignRequest(str(body.target_url),body.provider,body.method,body.prompt_field,body.headers,body.body_template,body.timeout,body.max_turns))
    return {'target':result.target,'provider':result.provider,'metadata':result.metadata,'observations':[o.__dict__ for o in result.observations],'findings':result.findings,'disclaimer':'Authorized, bounded defensive testing only.'}

@router.post('/retest')
async def retest(body: RetestBody,_=Depends(get_local_operator)):
    result=await run_retest(RetestRequest(str(body.target_url),body.provider,body.prompt_field,body.headers,body.body_template,body.original_finding,body.timeout))
    return result

@router.post('/rag-fixture')
def rag_fixture(body:RAGFixtureBody,_=Depends(get_local_operator)):
    return analyze_rag_fixture(body.documents)

@router.post('/agent-policy')
def agent_policy(body:AgentPolicyBody,_=Depends(get_local_operator)):
    return evaluate_agent_policy(body.tools,set(body.allowed_actions))
