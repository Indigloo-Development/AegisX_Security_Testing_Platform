from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.ai_evaluation.engine import BENCHMARK_CASES, evaluate_benchmark, compare_models, campaign_analytics, calculate_ai_risk

router=APIRouter(prefix='/api/ai-evaluation-v25', tags=['ai-evaluation-v25'])

class BenchmarkBody(BaseModel):
    results:list[dict[str,Any]]=Field(default_factory=list, max_length=500)

class ModelCompareBody(BaseModel):
    models:list[dict[str,Any]]=Field(default_factory=list, max_length=50)

class CampaignAnalyticsBody(BaseModel):
    campaigns:list[dict[str,Any]]=Field(default_factory=list, max_length=500)

class RiskBody(BaseModel):
    metrics:dict[str,Any]=Field(default_factory=dict)

@router.get('/suite')
def suite(_=Depends(get_local_operator)):
    return {'name':'AegisX AI Security Benchmark v25','case_count':len(BENCHMARK_CASES),'families':sorted({c.family for c in BENCHMARK_CASES}),'cases':[c.to_dict() for c in BENCHMARK_CASES]}

@router.post('/benchmark')
def benchmark(body:BenchmarkBody,_=Depends(get_local_operator)):
    return evaluate_benchmark(body.results)

@router.post('/compare-models')
def compare(body:ModelCompareBody,_=Depends(get_local_operator)):
    return compare_models(body.models)

@router.post('/campaign-analytics')
def analytics(body:CampaignAnalyticsBody,_=Depends(get_local_operator)):
    return campaign_analytics(body.campaigns)

@router.post('/risk')
def risk(body:RiskBody,_=Depends(get_local_operator)):
    return calculate_ai_risk(body.metrics)
