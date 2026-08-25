from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Any
from app.scanners.web.validation import (
    analyze_reflection_and_dom, analyze_injection_errors, analyze_csrf_and_sessions,
    analyze_session_rotation, analyze_workflow, WorkflowStep,
)

router = APIRouter(prefix="/api/commercial/web-validation", tags=["Commercial Web Validation"])

class ResponseAnalysisRequest(BaseModel):
    url: str
    body: str = ""
    headers: dict[str, str] = Field(default_factory=dict)

class CSRFRequest(BaseModel):
    url: str
    html: str = ""
    headers: dict[str, str] = Field(default_factory=dict)

class SessionRotationRequest(BaseModel):
    before_cookies: list[str] = Field(default_factory=list)
    after_cookies: list[str] = Field(default_factory=list)

class WorkflowRequest(BaseModel):
    steps: list[dict[str, Any]] = Field(default_factory=list, min_length=1, max_length=100)

@router.post("/analyze-response")
def analyze_response(request: ResponseAnalysisRequest):
    return {"findings": analyze_reflection_and_dom(request.body, request.url) + analyze_injection_errors(request.body, request.url)}

@router.post("/analyze-csrf")
def analyze_csrf(request: CSRFRequest):
    return {"findings": analyze_csrf_and_sessions(html=request.html, response_headers=request.headers, request_url=request.url)}

@router.post("/analyze-session-rotation")
def session_rotation(request: SessionRotationRequest):
    return {"findings": analyze_session_rotation(request.before_cookies, request.after_cookies)}

@router.post("/analyze-workflow")
def analyze_business_workflow(request: WorkflowRequest):
    steps = [WorkflowStep(**item) for item in request.steps]
    result = analyze_workflow(steps)
    return {"findings": result.findings, "warnings": result.warnings, "steps": result.normalized_steps}
