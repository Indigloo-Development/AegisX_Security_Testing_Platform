from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from app.scanners.api.common.http import fetch, joined, normalize_base


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def scan_soap(target_url: str) -> tuple[list[dict[str, Any]], list[dict]]:
    base = normalize_base(target_url)
    candidates = [base] if "?wsdl" in base.lower() or base.lower().endswith("wsdl") else [base + ("&" if "?" in base else "?") + "wsdl", base + ".wsdl"]
    for candidate in dict.fromkeys(candidates):
        try:
            response = fetch(candidate)
        except Exception:
            continue
        if response.status_code >= 400 or ("xml" not in response.content_type and "definitions" not in response.body[:500].lower()):
            continue
        try:
            root = ET.fromstring(response.body)
        except ET.ParseError:
            continue
        services: list[str] = []
        ports: list[dict[str, str]] = []
        operations: list[str] = []
        for node in root.iter():
            name = node.attrib.get("name")
            local = _local(node.tag)
            if local == "service" and name:
                services.append(name)
            elif local == "port" and name:
                ports.append({"name": name, "binding": node.attrib.get("binding", "")})
            elif local == "operation" and name:
                operations.append(name)
        findings = [{
            "finding_key": "SOAP-WSDL-DISCOVERED",
            "title": "SOAP WSDL discovered",
            "severity": "info",
            "confidence": "confirmed",
            "category": "API Discovery",
            "endpoint": candidate,
            "description": f"Discovered SOAP metadata with {len(services)} service(s), {len(ports)} port(s) and {len(operations)} operation declarations.",
            "evidence": {"services": services, "ports": ports, "operations": operations[:200]},
            "remediation": "Review whether WSDL exposure is required externally and enforce strict XML parsing, authentication and authorization on SOAP operations.",
        }]
        return [{"wsdl": candidate, "services": services, "ports": ports, "operations": operations[:200]}], findings
    return [], []
