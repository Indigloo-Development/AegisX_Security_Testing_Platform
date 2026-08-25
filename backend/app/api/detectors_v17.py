from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field
from app.rules import RuleEngine, ScanContext

router = APIRouter(prefix="/api/detectors-v17", tags=["Detector Library v17"])
engine = RuleEngine()

class DetectorRequest(BaseModel):
    url: str
    protocol: str = "web"
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    metadata: dict = Field(default_factory=dict)
    rule_keys: list[str] | None = None

@router.get("/catalog")
def catalog(protocol: str | None = None, family: str | None = None):
    rules = engine.list_rules(protocol=protocol, family=family)
    return {"total": len(rules), "rules": [
        {"key": r.key, "title": r.title, "family": r.family, "severity": r.severity,
         "confidence": r.confidence, "protocols": list(r.protocols), "owasp": list(r.owasp),
         "cwe": list(r.cwe), "tags": list(r.tags)} for r in rules if r.detector == "wave17"
    ]}

@router.post("/evaluate")
def evaluate(req: DetectorRequest):
    ctx = ScanContext(url=req.url, protocol=req.protocol, method=req.method,
                      headers={k.lower(): v for k, v in req.headers.items()},
                      body=req.body, metadata=req.metadata)
    selected = req.rule_keys or [r.key for r in engine.list_rules(protocol=req.protocol) if r.detector == "wave17"]
    findings = engine.evaluate(ctx, selected)
    return {"total": len(findings), "findings": [f.as_dict() for f in findings]}
