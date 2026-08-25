from __future__ import annotations

import json
from typing import Any
from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from app.api.deps import get_local_operator
from app.reporting.engine_v26 import build_report, to_csv_report, to_html_report, to_json_report, to_sarif

router = APIRouter(prefix="/api/reporting-v26", tags=["reporting-v26"])

class ReportBody(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    metadata: dict[str, Any] = Field(default_factory=dict)

@router.post("/json")
def json_report(body: ReportBody, _=Depends(get_local_operator)):
    return build_report(body.findings, body.metadata)

@router.post("/sarif")
def sarif_report(body: ReportBody, _=Depends(get_local_operator)):
    return to_sarif(body.findings)

@router.post("/csv", response_class=PlainTextResponse)
def csv_report(body: ReportBody, _=Depends(get_local_operator)):
    return to_csv_report(body.findings)

@router.post("/html", response_class=PlainTextResponse)
def html_report(body: ReportBody, _=Depends(get_local_operator)):
    return to_html_report(build_report(body.findings, body.metadata))

@router.post("/compliance")
def compliance_report(body: ReportBody, _=Depends(get_local_operator)):
    return build_report(body.findings, body.metadata)["compliance_crosswalk"]

@router.post("/evidence-timeline")
def evidence_report(body: ReportBody, _=Depends(get_local_operator)):
    return build_report(body.findings, body.metadata)["evidence_timeline"]
