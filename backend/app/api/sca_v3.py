from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.models import User
from app.scanners.sca_v3.engine import SCAReachabilityEngine

router=APIRouter(prefix="/api/sca-v3",tags=["sca-v3-reachability"])
_engine=SCAReachabilityEngine()

class AnalyzeRequest(BaseModel):
    source_path:str=Field(min_length=1,max_length=1000)
    profile:str="deep"
    include_dev:bool=False

@router.post("/analyze")
def analyze(body:AnalyzeRequest,user:User=Depends(get_local_operator)):
    try:
        r=_engine.analyze(body.source_path,body.profile,body.include_dev)
    except ValueError as exc:
        raise HTTPException(status_code=400,detail=str(exc)) from exc
    return r.__dict__
