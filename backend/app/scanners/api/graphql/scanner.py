from __future__ import annotations

from typing import Any

from app.scanners.api.common.http import fetch, normalize_base

_INTROSPECTION = {
    "query": "query AegisXIntrospection { __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind } } }"
}


def scan_graphql(target_url: str) -> tuple[list[dict[str, Any]], list[dict]]:
    url = normalize_base(target_url)
    result: list[dict[str, Any]] = []
    findings: list[dict] = []
    candidates = [url]
    if not url.endswith("/graphql"):
        candidates.extend([url + "/graphql", url + "/api/graphql"])
    for candidate in dict.fromkeys(candidates):
        try:
            response = fetch(candidate, method="POST", json_body=_INTROSPECTION)
        except Exception:
            continue
        if response.status_code >= 400 or "json" not in response.content_type:
            continue
        try:
            payload = __import__("json").loads(response.body)
        except Exception:
            continue
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        schema = data.get("__schema") if isinstance(data, dict) else None
        if not isinstance(schema, dict):
            continue
        types = [t for t in (schema.get("types") or []) if isinstance(t, dict) and t.get("name")]
        result.append({"url": candidate, "query_type": (schema.get("queryType") or {}).get("name"), "mutation_type": (schema.get("mutationType") or {}).get("name"), "type_count": len(types), "types": types[:200]})
        findings.append({
            "finding_key": "GRAPHQL-INTROSPECTION-ENABLED",
            "title": "GraphQL introspection is enabled",
            "severity": "medium",
            "confidence": "confirmed",
            "category": "API Security",
            "endpoint": candidate,
            "description": "The GraphQL endpoint accepted an introspection query and returned schema metadata. Exposure may be appropriate in development but should be reviewed for production deployments.",
            "evidence": {"query_type": (schema.get("queryType") or {}).get("name"), "mutation_type": (schema.get("mutationType") or {}).get("name"), "type_count": len(types)},
            "remediation": "Disable or restrict introspection in production where it is not required; enforce authorization at resolver/field level regardless of introspection status.",
        })
        return result, findings
    return result, findings
