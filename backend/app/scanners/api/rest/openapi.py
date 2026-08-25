from __future__ import annotations

import json
from typing import Any

from app.scanners.api.common.http import fetch, joined, normalize_base
from app.scanners.api.common.models import Endpoint


COMMON_SPECS = [
    "/openapi.json", "/openapi.yaml", "/openapi.yml", "/swagger.json", "/swagger.yaml", "/api/openapi.json", "/api/swagger.json"
]
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def parse_spec(data: dict[str, Any], base_url: str, source: str) -> tuple[list[Endpoint], list[dict]]:
    findings: list[dict] = []
    endpoints: list[Endpoint] = []
    paths = data.get("paths") or {}
    server_base = base_url
    servers = data.get("servers") or []
    if servers and isinstance(servers[0], dict) and servers[0].get("url"):
        server_base = servers[0]["url"]
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common_params = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params: list[str] = []
            for p in common_params + (op.get("parameters", []) if isinstance(op.get("parameters"), list) else []):
                if isinstance(p, dict) and p.get("name"):
                    params.append(str(p["name"]))
            endpoints.append(Endpoint(
                method=method.upper(), path=path, url=joined(server_base, path), source=source,
                operation_id=op.get("operationId"), parameters=params,
                auth_required=bool(op.get("security")) if "security" in op else None,
                content_types=[str(x) for x in (op.get("requestBody", {}).get("content", {}) or {}).keys()] if isinstance(op.get("requestBody"), dict) else [],
                tags=[str(x) for x in (op.get("tags") or [])],
            ))
    components = data.get("components") or {}
    security_schemes = components.get("securitySchemes") or {}
    if not security_schemes and data.get("securityDefinitions"):
        security_schemes = data.get("securityDefinitions") or {}
    if security_schemes:
        kinds = {str(v.get("type", "unknown")).lower() for v in security_schemes.values() if isinstance(v, dict)}
        if kinds:
            findings.append({
                "finding_key": "API-SPEC-AUTH-SCHEME",
                "title": "API security scheme inventory requires review",
                "severity": "info",
                "confidence": "confirmed",
                "category": "API Security",
                "endpoint": source,
                "description": f"OpenAPI exposes security schemes: {sorted(kinds)}. Validate that every sensitive operation enforces the intended scheme.",
                "evidence": {"security_schemes": security_schemes},
                "remediation": "Review global and operation-level security requirements and enforce least-privilege authorization.",
            })
    return endpoints, findings


def discover_openapi(target_url: str) -> tuple[list[Endpoint], list[dict]]:
    base = normalize_base(target_url)
    candidates: list[str] = []
    if any(base.lower().endswith(x) for x in (".json", ".yaml", ".yml")) or "swagger" in base.lower() or "openapi" in base.lower():
        candidates.append(base)
    candidates.extend(joined(base, p) for p in COMMON_SPECS)

    seen: set[str] = set()
    endpoints: list[Endpoint] = []
    findings: list[dict] = []
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            result = fetch(candidate)
        except Exception:
            continue
        if result.status_code >= 400:
            continue
        body = result.body.lstrip()
        data: dict[str, Any] | None = None
        if "json" in result.content_type or body.startswith("{"):
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    data = parsed
            except json.JSONDecodeError:
                pass
        # YAML is optional and handled when PyYAML is installed.
        if data is None and ("yaml" in result.content_type or candidate.endswith((".yaml", ".yml"))):
            try:
                import yaml  # type: ignore
                parsed = yaml.safe_load(body)
                if isinstance(parsed, dict):
                    data = parsed
            except Exception:
                data = None
        if not data or not (data.get("paths") or data.get("swagger") or data.get("openapi")):
            continue
        eps, f = parse_spec(data, base, candidate)
        endpoints.extend(eps)
        findings.extend(f)
        findings.append({
            "finding_key": "API-SPEC-DISCOVERED",
            "title": "API specification discovered",
            "severity": "info",
            "confidence": "confirmed",
            "category": "API Discovery",
            "endpoint": candidate,
            "description": f"Discovered an API specification containing {len(eps)} HTTP operations.",
            "evidence": {"spec_url": candidate, "endpoint_count": len(eps), "openapi": data.get("openapi"), "swagger": data.get("swagger")},
            "remediation": "Restrict exposure of API documentation/specification where appropriate and ensure it does not reveal secrets or internal-only operations.",
        })
        break
    return endpoints, findings
