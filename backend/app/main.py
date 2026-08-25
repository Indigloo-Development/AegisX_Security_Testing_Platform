import json
import time
import uuid
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from sqlalchemy import text

from app.core.config import settings
from app.core.logging import configure_logging
from app.db.session import Base, engine
from app.models import models  # noqa: F401
from app.schema_bootstrap import ensure_schema
from app.observability import HTTP_REQUESTS, HTTP_LATENCY, ACTIVE_REQUESTS, metrics_payload, event
from app.api import console_v42, observability_v34, observability_v35, projects, scans, findings, api_security, sca, specialized, ai_security, rag_security, agent_security, intelligence, enterprise, commercial, ai_security_v2, sca_v2, browser_scanner, deep_dast, web_validation, orchestration, rules, protocol_validation, authorization_v13, injection_v14, authentication_v15, api_fuzzing_v16, detectors_v17, websocket_v18, test_lab, knowledge, knowledge_live, sca_v3, ai_security_v3, ai_evaluation_v25, reporting_v26, finding_lifecycle_v27, monitoring_v28, alerting_v29, enterprise_v30, enterprise_v31, enterprise_v32, scaling_v33, security_operations_v36, enterprise_v37

configure_logging(settings.log_level)
log = logging.getLogger("aegisx")
Base.metadata.create_all(bind=engine)
ensure_schema()


app = FastAPI(
    title=settings.app_name,
    version="55.0.0",
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
)

@app.middleware("http")
async def security_and_request_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start = time.perf_counter()
    ACTIVE_REQUESTS.inc()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("Unhandled application error", extra={"request_id": request_id})
        response = JSONResponse(status_code=500, content={"detail": "Internal server error", "request_id": request_id})
    duration_seconds = time.perf_counter() - start
    duration_ms = round(duration_seconds * 1000, 2)
    route = getattr(getattr(request, "scope", {}), "get", lambda *_: None)("route")
    path_template = getattr(route, "path", None) or request.url.path
    HTTP_REQUESTS.labels(method=request.method, path_template=path_template, status=str(response.status_code)).inc()
    HTTP_LATENCY.labels(method=request.method, path_template=path_template).observe(duration_seconds)
    ACTIVE_REQUESTS.dec()
    event("http_request", request_id=request_id, method=request.method, path=path_template, status=response.status_code, duration_ms=duration_ms)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    if settings.environment.lower() == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    log.info("request", extra={"request_id": request_id},)
    response.headers["Server-Timing"] = f"app;dur={duration_ms}"
    return response

app.include_router(console_v42.router)
app.include_router(observability_v34.router)
app.include_router(observability_v35.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(api_security.router)
app.include_router(sca.router)
app.include_router(specialized.router)
app.include_router(ai_security.router)
app.include_router(rag_security.router)
app.include_router(agent_security.router)
app.include_router(intelligence.router)
app.include_router(enterprise.router)
app.include_router(commercial.router)
app.include_router(ai_security_v2.router)
app.include_router(sca_v2.router)
app.include_router(browser_scanner.router)
app.include_router(deep_dast.router)
app.include_router(web_validation.router)
app.include_router(orchestration.router)
app.include_router(rules.router)
app.include_router(protocol_validation.router)
app.include_router(authorization_v13.router)
app.include_router(injection_v14.router)
app.include_router(authentication_v15.router)
app.include_router(api_fuzzing_v16.router)
app.include_router(detectors_v17.router)
app.include_router(websocket_v18.router)
app.include_router(test_lab.router)
app.include_router(knowledge.router)
app.include_router(knowledge_live.router)
app.include_router(sca_v3.router)
app.include_router(ai_security_v3.router)
app.include_router(ai_evaluation_v25.router)
app.include_router(reporting_v26.router)
app.include_router(finding_lifecycle_v27.router)
app.include_router(monitoring_v28.router)
app.include_router(alerting_v29.router)
app.include_router(enterprise_v30.router)
app.include_router(enterprise_v31.router)
app.include_router(enterprise_v32.router)
app.include_router(scaling_v33.router)
app.include_router(security_operations_v36.router)
app.include_router(enterprise_v37.router)

ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / "runtime" / "artifacts"
ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
app.mount("/artifacts", StaticFiles(directory=str(ARTIFACT_ROOT)), name="artifacts")

@app.get("/")
def root():
    return {"name": settings.app_name, "version": "55.0.0", "status": "ready", "ui": "55.0.0"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "aegisx-backend"}

@app.get("/ready")
def ready():
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "ok"}
    except Exception:
        return JSONResponse(status_code=503, content={"status": "not_ready", "database": "unavailable"})

@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    payload, content_type = metrics_payload()
    return PlainTextResponse(payload, media_type=content_type)
