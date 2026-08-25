from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Any

from app.commercial.authentication_v15 import (
    AuthWorkflow, SessionObservation, analyze_jwt_usage, analyze_login_workflow,
    analyze_mfa_policy, analyze_oauth_oidc, analyze_session_observation,
)

router = APIRouter(prefix="/api/auth-security-v15", tags=["Authentication Security v15"])


class WorkflowRequest(BaseModel):
    name: str
    steps: list[dict[str, Any]] = Field(default_factory=list)
    requires_mfa: bool = False
    success_marker: str | None = None


@router.post("/workflow")
def workflow(payload: WorkflowRequest):
    findings = analyze_login_workflow(AuthWorkflow(payload.name, payload.steps, payload.requires_mfa, payload.success_marker))
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}


class SessionRequest(BaseModel):
    session_before: str | None = None
    session_after_login: str | None = None
    session_after_privilege_change: str | None = None
    session_after_logout: str | None = None
    token_before: str | None = None
    token_after: str | None = None


@router.post("/session")
def session(payload: SessionRequest):
    findings = analyze_session_observation(SessionObservation(**payload.model_dump()))
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}


class OAuthRequest(BaseModel):
    config: dict[str, Any] = Field(default_factory=dict)


@router.post("/oauth-oidc")
def oauth_oidc(payload: OAuthRequest):
    findings = analyze_oauth_oidc(payload.config)
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}


class MFARequest(BaseModel):
    policy: dict[str, Any] = Field(default_factory=dict)


@router.post("/mfa")
def mfa(payload: MFARequest):
    findings = analyze_mfa_policy(payload.policy)
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}


class JWTUsageRequest(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.post("/jwt-usage")
def jwt_usage(payload: JWTUsageRequest):
    findings = analyze_jwt_usage(payload.metadata)
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}
