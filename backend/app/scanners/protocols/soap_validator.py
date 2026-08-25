from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any

@dataclass(frozen=True)
class ProtocolIssue:
    key: str
    severity: str
    confidence: str
    title: str
    evidence: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

class SOAPValidator:
    def analyze(self, xml: str, metadata: dict[str, Any] | None = None) -> list[ProtocolIssue]:
        metadata = metadata or {}
        issues: list[ProtocolIssue] = []
        lowered = xml.lower()
        has_doctype = "<!doctype" in lowered
        has_entity = "<!entity" in lowered
        if has_doctype and has_entity:
            issues.append(ProtocolIssue("SOAP-001", "critical", "high", "DTD/external entity declaration present", "XML contains DOCTYPE and ENTITY declarations", "Disable DTD/external entity processing."))
        if metadata.get("external_entities_enabled") is True:
            issues.append(ProtocolIssue("SOAP-002", "critical", "confirmed", "External entity processing enabled", "metadata.external_entities_enabled=true", "Disable external entity resolution."))
        if metadata.get("entity_expansion_limit") is None:
            issues.append(ProtocolIssue("SOAP-003", "medium", "potential", "Entity expansion limit not declared", "metadata.entity_expansion_limit is absent", "Apply parser depth/expansion/resource limits."))
        if re.search(r"<soap[^>]*:body\b", xml, re.I) and metadata.get("schema_validation") is False:
            issues.append(ProtocolIssue("SOAP-004", "medium", "potential", "SOAP schema validation disabled", "metadata.schema_validation=false", "Validate SOAP payloads against the expected XML Schema."))
        if metadata.get("transport") == "http" or (metadata.get("url", "").startswith("http://")):
            issues.append(ProtocolIssue("SOAP-005", "high", "confirmed", "SOAP transport is plaintext HTTP", "transport/http URL indicates HTTP", "Use HTTPS with certificate validation."))
        return issues
