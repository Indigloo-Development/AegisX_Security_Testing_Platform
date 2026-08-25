from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.rules.engine import RuleEngine
from app.rules.injection import create_oast_token
from app.rules.models import ScanContext

router = APIRouter(prefix="/api/injection-v14", tags=["Injection Validation"])
engine = RuleEngine()


class InjectionRequest(BaseModel):
    url: str
    protocol: str = "web"
    method: str = "GET"
    status_code: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    parameters: list[dict] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    rule_keys: list[str] | None = None


@router.post("/evaluate")
def evaluate(payload: InjectionRequest):
    ctx = ScanContext(
        url=payload.url,
        protocol=payload.protocol,
        method=payload.method,
        status_code=payload.status_code,
        headers={k.lower(): v for k, v in payload.headers.items()},
        body=payload.body,
        content_type=payload.content_type,
        parameters=payload.parameters,
        metadata=payload.metadata,
    )
    findings = engine.evaluate(ctx, payload.rule_keys)
    findings = [f for f in findings if f.rule_key.startswith("INJ-")]
    return {"total": len(findings), "findings": [f.as_dict() for f in findings]}


class OASTTokenRequest(BaseModel):
    scan_id: str
    length: int = 24


@router.post("/oast-token")
def oast_token(payload: OASTTokenRequest):
    return {"token": create_oast_token(payload.scan_id, payload.length)}
