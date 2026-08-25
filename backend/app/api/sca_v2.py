from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Any
from app.api.deps import get_local_operator
from app.models import User
from app.scanners.sca_v2.engine import SCAIntelligenceEngine

router = APIRouter(prefix="/api/sca-v2", tags=["sca-v2"])
_engine = SCAIntelligenceEngine()

class AnalyzeRequest(BaseModel):
    source_path: str = Field(min_length=1, max_length=1000)
    profile: str = "standard"
    policy: dict[str, Any] = {}

class SBOMDiffRequest(BaseModel):
    old_sbom: dict[str, Any]
    new_sbom: dict[str, Any]

class AdvisoryImportRequest(BaseModel):
    records: list[dict[str, Any]] = Field(min_length=1, max_length=1000)

@router.post("/analyze")
def analyze(body: AnalyzeRequest, user: User = Depends(get_local_operator)):
    try:
        result = _engine.analyze(body.source_path, body.profile, body.policy)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "source_path": body.source_path,
        "profile": body.profile,
        "dependency_count": len(result.dependencies),
        "dependencies": result.dependencies,
        "graph": result.graph,
        "intelligence": result.intelligence,
        "license_assessments": result.license_assessments,
        "supply_chain_indicators": result.supply_chain_indicators,
        "policy": result.policy,
        "findings": result.findings,
    }

@router.post("/sbom/diff")
def sbom_diff(body: SBOMDiffRequest, user: User = Depends(get_local_operator)):
    return _engine.sbom_diff(body.old_sbom, body.new_sbom)

@router.post("/intel/import")
def import_intel(body: AdvisoryImportRequest, user: User = Depends(get_local_operator)):
    from app.scanners.sca_v2.intel import CATALOG
    # Only advisory metadata is imported; no code execution or network fetching occurs.
    added = _engine.provider.import_records(body.records)
    return {"added": added, "catalog_size": len(CATALOG)}
