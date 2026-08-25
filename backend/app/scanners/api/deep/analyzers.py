from __future__ import annotations
import json
import re
from typing import Any
from .rules import RULE_INDEX


def make_finding(key: str, endpoint: str, evidence: dict[str, Any], confidence: str = "potential") -> dict[str, Any]:
    r = RULE_INDEX[key]
    return {"finding_key": r.key, "title": r.title, "severity": r.severity, "confidence": confidence, "category": r.category,
            "description": r.description, "remediation": r.remediation, "endpoint": endpoint,
            "evidence": evidence, "owasp": list(r.owasp), "cwe": list(r.cwe)}


def build_authorization_matrix(endpoints: list[dict[str, Any]], identities: list[str]) -> list[dict[str, Any]]:
    matrix = []
    for endpoint in endpoints:
        if endpoint.get("security_required") is False:
            continue
        for identity in identities:
            matrix.append({"identity": identity, "method": endpoint.get("method", "GET"), "url": endpoint.get("url", ""),
                           "operation_id": endpoint.get("operation_id"), "expected": "authorized-or-denied-by-policy"})
    return matrix


def build_safe_negative_cases(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    method = str(endpoint.get("method", "GET")).upper()
    url = endpoint.get("url", "")
    cases = []
    # Only proposes cases; it does not execute state-changing mutations.
    if method in {"GET", "HEAD", "OPTIONS"}:
        cases.extend([
            {"case": "empty_optional_parameters", "method": method, "url": url, "mode": "safe-proposed"},
            {"case": "unexpected_query_parameter", "method": method, "url": url, "mode": "safe-proposed"},
        ])
    if endpoint.get("parameters"):
        for parameter in endpoint["parameters"][:10]:
            cases.append({"case": "boundary_length", "parameter": parameter, "method": method, "url": url, "mode": "safe-proposed"})
    return cases


def analyze_openapi_document(document: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    paths = document.get("paths") or {}
    components = document.get("components") or {}
    schemas = components.get("schemas") or {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"} or not isinstance(op, dict):
                continue
            endpoint = f"{method.upper()} {path}"
            if "security" not in op and "security" not in document:
                findings.append(make_finding("API-AUTH-001", endpoint, {"operation": op.get("operationId")}))
            params = [p for p in (op.get("parameters") or []) if isinstance(p, dict)]
            for param in params:
                schema = param.get("schema") if isinstance(param.get("schema"), dict) else {}
                if schema.get("type") == "string" and not any(k in schema for k in ("maxLength", "pattern", "format", "enum")):
                    findings.append(make_finding("API-SCHEMA-002", endpoint, {"parameter": param.get("name")}))
            request_body = op.get("requestBody") if isinstance(op.get("requestBody"), dict) else {}
            content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
            for media in content.values():
                if not isinstance(media, dict):
                    continue
                schema_ref = media.get("schema") if isinstance(media.get("schema"), dict) else {}
                if isinstance(schema_ref, dict) and "$ref" in schema_ref:
                    schema_name = schema_ref["$ref"].rsplit("/", 1)[-1]
                    schema = schemas.get(schema_name, {}) if isinstance(schemas, dict) else {}
                    if isinstance(schema, dict) and schema.get("type") == "object" and schema.get("additionalProperties", True) is not False:
                        findings.append(make_finding("API-SCHEMA-001", endpoint, {"schema": schema_name, "additionalProperties": schema.get("additionalProperties", True)}))
            if any(re.search(r"(?:page|limit|offset|size)", str(x.get("name", "")), re.I) for x in params):
                findings.append(make_finding("API-RES-001", endpoint, {"pagination_parameters": [x.get("name") for x in params]}))
    for name, schema in schemas.items() if isinstance(schemas, dict) else []:
        if isinstance(schema, dict) and any(k.lower() in name.lower() for k in ("error", "exception", "debug")):
            findings.append(make_finding("API-ERROR-001", f"schema:{name}", {"schema": schema}))
    return findings


def analyze_graphql_schema(schema: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    types = [t for t in (schema.get("types") or []) if isinstance(t, dict)]
    nested = []
    mutations = []
    for t in types:
        fields = t.get("fields") or []
        if t.get("name") == "Mutation":
            mutations.extend([f.get("name") for f in fields if isinstance(f, dict) and f.get("name")])
        if len(fields) > 10:
            nested.append(t.get("name"))
    if nested:
        findings.append(make_finding("API-GQL-001", "GraphQL schema", {"large_types": nested[:50]}))
    if mutations:
        findings.append(make_finding("API-GQL-002", "GraphQL Mutation", {"mutations": mutations[:100]}))
    return findings


def analyze_soap_document(xml_text: str) -> list[dict[str, Any]]:
    findings = []
    low = xml_text.lower()
    if "<!doctype" in low or "<!entity" in low:
        findings.append(make_finding("API-SOAP-001", "SOAP/WSDL", {"xml_declarations": [x for x in ("doctype", "entity") if x in low]}, "confirmed"))
    else:
        findings.append(make_finding("API-SOAP-001", "SOAP/WSDL", {"check": "XML parser hardening required at runtime"}, "potential"))
    return findings


def analyze_grpc_proto(proto_text: str, reflection_enabled: bool = False) -> list[dict[str, Any]]:
    findings = []
    if reflection_enabled:
        findings.append(make_finding("API-GRPC-001", "gRPC reflection", {"reflection": True}, "confirmed"))
    if "google.protobuf.Empty" in proto_text and "grpc.reflection.v1alpha" in proto_text:
        findings.append(make_finding("API-GRPC-001", "gRPC proto", {"reflection_import": True}, "potential"))
    return findings
