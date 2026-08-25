from __future__ import annotations
from typing import Any
from .analyzers import build_authorization_matrix, build_safe_negative_cases, analyze_openapi_document, analyze_graphql_schema, analyze_soap_document, analyze_grpc_proto

class APIDeepEngine:
    """Evidence-first API security analysis. Active mutation is intentionally disabled here; callers receive bounded cases to execute inside an authorized profile."""
    def analyze_openapi(self, document: dict[str, Any], identities: list[str] | None = None) -> dict[str, Any]:
        endpoints = []
        for path, item in (document.get("paths") or {}).items():
            if not isinstance(item, dict): continue
            for method, op in item.items():
                if method.lower() not in {"get","post","put","patch","delete","options","head"} or not isinstance(op, dict): continue
                params = [str(p.get("name")) for p in (op.get("parameters") or []) if isinstance(p, dict) and p.get("name")]
                endpoints.append({"method": method.upper(), "url": path, "parameters": params, "security_required": (bool(op.get("security")) if "security" in op else None), "operation_id": op.get("operationId"), "tags": op.get("tags") or []})
        negatives = [case for e in endpoints for case in build_safe_negative_cases(e)]
        matrix = build_authorization_matrix(endpoints, identities or [])
        findings = analyze_openapi_document(document)
        return {"findings": findings, "endpoint_count": len(endpoints), "authorization_matrix": matrix, "negative_cases": negatives, "endpoints": endpoints}

    def analyze_graphql(self, schema: dict[str, Any]) -> dict[str, Any]:
        return {"findings": analyze_graphql_schema(schema)}

    def analyze_soap(self, xml_text: str) -> dict[str, Any]:
        return {"findings": analyze_soap_document(xml_text)}

    def analyze_grpc(self, proto_text: str, reflection_enabled: bool = False) -> dict[str, Any]:
        return {"findings": analyze_grpc_proto(proto_text, reflection_enabled), "reflection_enabled": reflection_enabled}
