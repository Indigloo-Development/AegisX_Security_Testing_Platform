from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.rules import RuleEngine, ScanContext, rule_catalog_summary

router = APIRouter(prefix="/api/rules", tags=["Rule Engine"])
engine = RuleEngine()

class RuleScanRequest(BaseModel):
    url: str
    protocol: str = "web"
    method: str = "GET"
    status_code: int = 200
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    parameters: list[dict] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)
    rule_keys: list[str] | None = None

@router.get("/catalog")
def catalog(family: str | None = None, protocol: str | None = None):
    rules = engine.list_rules(family=family, protocol=protocol)
    return {"summary": rule_catalog_summary(), "rules": [
        {
            "key": r.key, "title": r.title, "family": r.family, "severity": r.severity,
            "confidence": r.confidence, "protocols": list(r.protocols),
            "owasp": list(r.owasp), "cwe": list(r.cwe), "tags": list(r.tags),
        } for r in rules
    ]}

@router.post("/evaluate")
def evaluate(payload: RuleScanRequest):
    ctx = ScanContext(
        url=payload.url,
        protocol=payload.protocol,
        method=payload.method,
        status_code=payload.status_code,
        headers={k.lower(): v for k, v in payload.headers.items()},
        body=payload.body,
        parameters=payload.parameters,
        metadata=payload.metadata,
    )
    findings = engine.evaluate(ctx, payload.rule_keys)
    return {
        "total": len(findings),
        "findings": [item.as_dict() for item in findings],
    }
