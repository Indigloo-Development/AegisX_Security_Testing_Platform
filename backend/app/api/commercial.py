from __future__ import annotations
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from app.commercial.engine import CommercialEngine
from app.commercial.dast.authenticated import AuthenticatedWebScanner
from app.commercial.models import AuthProfile, ScanPolicy
from app.commercial.threat_intel import enrich
from app.scanners.web.advanced.report import rule_catalog

router = APIRouter(prefix="/api/commercial", tags=["Commercial Expansion"])

class WebActiveRequest(BaseModel):
    target_url: str
    profile: str = "commercial-safe-active"
    auth: dict | None = None
    policy: dict = Field(default_factory=dict)

class BatchWebRequest(BaseModel):
    target_urls: list[str] = Field(min_length=1, max_length=100)
    policy: dict = Field(default_factory=dict)

class IntelRequest(BaseModel):
    ecosystem: str
    name: str
    version: str

@router.post("/web/active")
def active_web(req: WebActiveRequest):
    try:
        policy = ScanPolicy(**req.policy)
        auth = AuthProfile(**req.auth) if req.auth else None
        return CommercialEngine(policy).scan_web_active(req.target_url, auth)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/web/batch")
def batch_web(req: BatchWebRequest):
    try:
        return CommercialEngine(ScanPolicy(**req.policy)).batch_web(req.target_urls)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@router.post("/sca/intel")
def sca_intel(req: IntelRequest):
    return {"component": req.model_dump(), "advisories": enrich(req.model_dump())}


class AuthWebRequest(BaseModel):
    target_url: str
    profile: str = "deep"
    auth: dict | None = None
    policy: dict = Field(default_factory=dict)

@router.post("/web/deep")
def deep_web(req: AuthWebRequest):
    try:
        policy = ScanPolicy(**req.policy)
        auth = AuthProfile(**req.auth) if req.auth else None
        result = AuthenticatedWebScanner(policy, auth).run(req.target_url, req.profile)
        return {"result": result.__dict__, "profile": req.profile, "auth_profile": auth.sanitized() if auth else None}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/web/rules")
def web_rule_catalog():
    return {"count": len(rule_catalog()), "rules": rule_catalog()}
