from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class APIRule:
    key: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    owasp: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()

RULES = [
    APIRule("API-AUTH-001", "Operation lacks an explicit security requirement", "medium", "Authentication", "The imported operation does not declare an explicit security requirement.", "Review whether the operation is intentionally public and define an explicit security requirement for protected operations.", ("API2:2023",)),
    APIRule("API-AUTHZ-001", "Authorization matrix requires object-level validation", "high", "Authorization", "An object-oriented endpoint should be tested across identities to validate BOLA resistance.", "Perform authenticated differential testing using two authorized principals and verify object ownership enforcement.", ("API1:2023",), ("CWE-639",)),
    APIRule("API-AUTHZ-002", "Function-level authorization requires role comparison", "high", "Authorization", "Privileged operation should be compared across lower-privilege identities.", "Verify server-side role enforcement for every privileged function.", ("API5:2023",), ("CWE-862",)),
    APIRule("API-RES-001", "Potential unrestricted resource consumption", "medium", "Resource Management", "An endpoint accepts potentially unbounded list/page controls.", "Set bounded pagination and server-side maximums; apply rate and cost controls.", ("API4:2023",)),
    APIRule("API-SCHEMA-001", "Schema allows additional object properties", "medium", "Input Validation", "An object schema permits unspecified properties, increasing mass-assignment risk.", "Reject unexpected properties or explicitly allow a reviewed field set.", ("API3:2023",)),
    APIRule("API-SCHEMA-002", "Nullable or unconstrained string input", "low", "Input Validation", "A string input has few constraints and should receive business-context validation.", "Define length, format, pattern or enum constraints where appropriate.", ("API3:2023",)),
    APIRule("API-ERROR-001", "Verbose API error model disclosed", "medium", "Error Handling", "An API schema describes internal exception/debug fields.", "Return stable external error objects and keep internal diagnostic fields server-side.", ("API8:2023",), ("CWE-209",)),
    APIRule("API-GQL-001", "GraphQL query depth requires a limit", "medium", "GraphQL", "Nested schema types can create high-cost queries if no depth policy is enforced.", "Apply query-depth and complexity limits at the gateway or GraphQL runtime.", ("API4:2023",)),
    APIRule("API-GQL-002", "GraphQL mutation inventory requires resolver authorization review", "high", "GraphQL", "Mutation operations can change state and require field/resolver-level authorization.", "Review each mutation resolver for explicit authorization and ownership controls.", ("API5:2023",)),
    APIRule("API-SOAP-001", "SOAP endpoint should enforce XML parser hardening", "high", "SOAP", "XML parsing should be hardened against external entity resolution and unsafe expansion.", "Disable external entities and DTD processing and enforce resource limits.", ("API8:2023",), ("CWE-611",)),
    APIRule("API-GRPC-001", "gRPC reflection exposure requires review", "medium", "gRPC", "Reflection can disclose service and method metadata.", "Restrict reflection to trusted environments or authenticated administrative contexts.", ("API9:2023",)),
]
RULE_INDEX = {x.key: x for x in RULES}
