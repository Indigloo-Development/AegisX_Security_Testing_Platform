from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, HttpUrl
from app.api.deps import get_local_operator
from app.scanners.rag import RAGSecurityScanner, RAGTarget

router = APIRouter(prefix="/api/rag-security", tags=["rag-security"])


class RAGScanRequest(BaseModel):
    target_url: HttpUrl
    query_field: str = Field(default="query", min_length=1, max_length=80)
    method: str = Field(default="POST", pattern="^(POST|PUT|PATCH)$")
    headers: dict[str, str] = Field(default_factory=dict)
    body_template: dict = Field(default_factory=dict)
    timeout: float = Field(default=15.0, ge=2, le=30)
    tenant_a_header: str | None = Field(default=None, max_length=100)
    tenant_b_header: str | None = Field(default=None, max_length=100)


@router.post("/scan")
async def rag_scan(req: RAGScanRequest, _=Depends(get_local_operator)):
    if req.target_url.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS targets are supported")
    target = RAGTarget(
        str(req.target_url), req.method, req.query_field, req.headers,
        req.body_template, req.timeout, req.tenant_a_header, req.tenant_b_header,
    )
    result = await RAGSecurityScanner().run(target)
    return {
        "target": result.target,
        "metadata": result.metadata,
        "probes": [p.__dict__ for p in result.probes],
        "findings": result.findings,
        "disclaimer": "Run only against systems you are authorized to assess. RAG findings require application and authorization-context validation.",
    }
