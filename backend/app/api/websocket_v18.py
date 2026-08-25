from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel, Field
from app.scanners.web.dom_analysis_v18 import analyze_dom_dataflow
from app.scanners.websocket.analyzer_v18 import analyze_handshake, analyze_message

router = APIRouter(prefix="/api/websocket-v18", tags=["WebSocket & DOM Security v18"])

class DOMRequest(BaseModel):
    source: str = Field(min_length=1, max_length=500_000)

class HandshakeRequest(BaseModel):
    url: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)

class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=200_000)
    direction: str = "server-to-client"
    metadata: dict = Field(default_factory=dict)

@router.post("/dom/analyze")
def dom_analyze(req: DOMRequest):
    flows = analyze_dom_dataflow(req.source)
    return {"total": len(flows), "flows": [f.__dict__ for f in flows]}

@router.post("/handshake/analyze")
def websocket_handshake(req: HandshakeRequest):
    findings = analyze_handshake(url=req.url, request_headers=req.request_headers, response_headers=req.response_headers)
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}

@router.post("/message/analyze")
def websocket_message(req: MessageRequest):
    findings = analyze_message(message=req.message, direction=req.direction, metadata=req.metadata)
    return {"total": len(findings), "findings": [f.__dict__ for f in findings]}
