from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.scanners.api.common.http import normalize_base
from app.scanners.api.rest.openapi import discover_openapi
from app.scanners.api.graphql.scanner import scan_graphql
from app.scanners.api.soap.scanner import scan_soap
from app.scanners.api.grpc.scanner import scan_grpc


@dataclass
class APIScanResult:
    findings: list[dict[str, Any]]
    inventory: dict[str, Any]


class APIScanner:
    """Safe API discovery and passive analysis engine for Phase 3."""

    def run(self, target_url: str, profile: str = "standard") -> APIScanResult:
        base = normalize_base(target_url)
        findings: list[dict[str, Any]] = []
        inventory: dict[str, Any] = {"target": base, "openapi": [], "graphql": [], "soap": [], "grpc": [], "rest_endpoints": []}

        endpoints, openapi_findings = discover_openapi(base)
        inventory["rest_endpoints"] = [e.as_dict() for e in endpoints]
        inventory["openapi"] = {"endpoint_count": len(endpoints)}
        findings.extend(openapi_findings)

        graphql_inventory, graphql_findings = scan_graphql(base)
        inventory["graphql"] = graphql_inventory
        findings.extend(graphql_findings)

        soap_inventory, soap_findings = scan_soap(base)
        inventory["soap"] = soap_inventory
        findings.extend(soap_findings)

        grpc_inventory, grpc_findings = scan_grpc(base)
        inventory["grpc"] = grpc_inventory
        findings.extend(grpc_findings)

        if not endpoints and not graphql_inventory and not soap_inventory:
            findings.append({
                "finding_key": "API-DISCOVERY-NOT-CONFIRMED",
                "title": "No API specification or GraphQL/SOAP metadata discovered",
                "severity": "info",
                "confidence": "potential",
                "category": "API Discovery",
                "endpoint": base,
                "description": "The safe discovery pass did not identify a standard OpenAPI/Swagger document, GraphQL introspection endpoint, or SOAP WSDL at the common locations.",
                "evidence": {"checked": ["OpenAPI/Swagger common paths", "GraphQL candidate paths", "SOAP WSDL candidates"]},
                "remediation": "Import an authoritative API specification or configure authenticated discovery for protected API inventories.",
            })
        return APIScanResult(findings=findings, inventory=inventory)
