from __future__ import annotations

from .models import RuleDefinition


def _r(key, title, family, severity, confidence, description, remediation, *, protocols=(), owasp=(), cwe=(), tags=(), detector="generic"):
    return RuleDefinition(key, title, family, severity, confidence, description, remediation, tuple(protocols), tuple(owasp), tuple(cwe), tuple(tags), detector)

# Reusable catalog. Individual implementations can activate deeper protocol-specific checks later.
_BASE = [
    _r("WEB-CSP-001", "Missing Content-Security-Policy", "Security Headers", "medium", "confirmed", "The response does not publish an enforced CSP header.", "Define an application-appropriate Content-Security-Policy and enforce it.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-693",), tags=("csp", "headers"), detector="header_absence"),
    _r("WEB-CSP-002", "Unsafe CSP source expression", "Security Headers", "high", "high", "The CSP permits an overly broad or unsafe source expression.", "Remove unsafe expressions and prefer nonces/hashes and tightly scoped origins.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-693",), tags=("csp",), detector="csp_unsafe"),
    _r("WEB-CSP-003", "CSP report-only policy", "Security Headers", "medium", "confirmed", "A CSP is present only in report-only mode and is not enforced.", "Move a validated CSP policy to enforced Content-Security-Policy.", protocols=("web",), owasp=("A02:2025",), tags=("csp",), detector="csp_report_only"),
    _r("WEB-CSP-004", "Overly broad CSP wildcard source", "Security Headers", "high", "high", "A CSP contains broad wildcard sources that substantially weaken policy isolation.", "Replace wildcards with explicit trusted origins and paths.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-693",), tags=("csp",), detector="csp_wildcard"),
    _r("WEB-HEAD-001", "Missing HSTS", "Security Headers", "medium", "confirmed", "HTTPS response does not advertise Strict-Transport-Security.", "Enable HSTS for HTTPS-only deployments after validating certificate and subdomain readiness.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-319",), tags=("headers", "tls"), detector="header_absence"),
    _r("WEB-HEAD-002", "Missing X-Content-Type-Options", "Security Headers", "low", "confirmed", "The response lacks nosniff protection.", "Set X-Content-Type-Options: nosniff.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-16",), tags=("headers",), detector="header_absence"),
    _r("WEB-HEAD-003", "Missing Referrer-Policy", "Security Headers", "low", "confirmed", "The response does not constrain referrer propagation.", "Set an application-appropriate Referrer-Policy.", protocols=("web",), owasp=("A02:2025",), tags=("headers",), detector="header_absence"),
    _r("WEB-CORS-001", "Wildcard CORS origin", "Cross-Origin", "medium", "high", "The endpoint accepts any origin according to Access-Control-Allow-Origin.", "Restrict CORS to explicit trusted origins.", protocols=("web", "api"), owasp=("A02:2025",), cwe=("CWE-942",), tags=("cors",), detector="cors_wildcard"),
    _r("WEB-CORS-002", "Wildcard CORS with credentials", "Cross-Origin", "high", "high", "Wildcard origin is combined with credentialed cross-origin access semantics.", "Use an explicit allowlist and avoid permissive credentialed CORS.", protocols=("web", "api"), owasp=("A01:2025", "A02:2025"), cwe=("CWE-942",), tags=("cors",), detector="cors_credentials"),
    _r("WEB-COOKIE-001", "Session cookie missing Secure", "Session Management", "medium", "confirmed", "A session cookie can be sent without the Secure attribute.", "Set Secure on authentication/session cookies.", protocols=("web",), owasp=("A07:2025",), cwe=("CWE-614",), tags=("cookie",), detector="cookie_secure"),
    _r("WEB-COOKIE-002", "Session cookie missing HttpOnly", "Session Management", "medium", "confirmed", "A session cookie is readable by client-side script.", "Set HttpOnly on authentication/session cookies unless script access is explicitly required.", protocols=("web",), owasp=("A07:2025",), cwe=("CWE-1004",), tags=("cookie",), detector="cookie_httponly"),
    _r("WEB-COOKIE-003", "Session cookie missing SameSite", "Session Management", "low", "confirmed", "A session cookie has no explicit SameSite attribute.", "Set an appropriate SameSite policy and validate OAuth/SSO workflows.", protocols=("web",), owasp=("A01:2025", "A07:2025"), tags=("cookie", "csrf"), detector="cookie_samesite"),
    _r("WEB-ERR-001", "Verbose server error disclosure", "Error Handling", "medium", "high", "The response contains a stack trace or framework error signature.", "Return generic external errors and log detailed diagnostics securely server-side.", protocols=("web", "api"), owasp=("A10:2025",), cwe=("CWE-209",), tags=("errors",), detector="error_signature"),
    _r("WEB-ERR-002", "Database error disclosure", "Error Handling", "high", "high", "The response contains database-specific error indicators.", "Suppress database diagnostics and use consistent external error responses.", protocols=("web", "api"), owasp=("A05:2025", "A10:2025"), cwe=("CWE-209",), tags=("database", "errors"), detector="db_error"),
    _r("WEB-INJ-001", "Reflected input requires XSS validation", "Injection", "medium", "potential", "User-controlled input is reflected into the response and needs context-aware output encoding validation.", "Apply context-appropriate output encoding and validate dangerous sinks.", protocols=("web",), owasp=("A05:2025",), cwe=("CWE-79",), tags=("xss", "reflection"), detector="reflection"),
    _r("WEB-INJ-002", "Potential DOM XSS source-to-sink path", "Injection", "high", "potential", "A controllable source reaches a potentially dangerous DOM sink.", "Use safe DOM APIs and sanitize/encode data before insertion.", protocols=("web",), owasp=("A05:2025",), cwe=("CWE-79",), tags=("xss", "dom"), detector="dom_xss"),
    _r("WEB-INJ-003", "SQL error-based injection indicator", "Injection", "high", "potential", "A database error signature was observed after controlled input variation.", "Use parameterized queries and validate input at the application boundary.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-89",), tags=("sqli",), detector="db_error"),
    _r("WEB-INJ-004", "Command execution error indicator", "Injection", "critical", "potential", "The response contains command-execution error signatures after controlled testing.", "Use safe process APIs, strict allowlists and avoid shell interpolation.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-78",), tags=("command-injection",), detector="command_error"),
    _r("WEB-FS-001", "Path traversal error indicator", "File Access", "high", "potential", "A filesystem/path traversal error signature was observed.", "Canonicalize paths and enforce strict filesystem allowlists.", protocols=("web", "api"), owasp=("A01:2025", "A05:2025"), cwe=("CWE-22",), tags=("path-traversal",), detector="path_error"),
    _r("WEB-SSRF-001", "SSRF validation candidate", "Server-Side Request", "high", "potential", "A parameter is a candidate for server-side URL fetching and requires controlled SSRF validation.", "Allowlist destinations and block private/link-local metadata ranges.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-918",), tags=("ssrf",), detector="url_parameter"),
    _r("WEB-SEC-001", "Clickjacking protection absent", "Browser Security", "medium", "confirmed", "No X-Frame-Options or frame-ancestors protection was observed.", "Use frame-ancestors in CSP and/or X-Frame-Options where appropriate.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-1021",), tags=("clickjacking",), detector="clickjacking"),
    _r("WEB-SEC-002", "Mixed content indicator", "Browser Security", "medium", "confirmed", "HTTPS page references an insecure HTTP resource.", "Serve all active and passive resources over HTTPS.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-319",), tags=("mixed-content",), detector="mixed_content"),
    _r("WEB-SEC-003", "Server technology disclosure", "Information Disclosure", "low", "confirmed", "Response headers disclose server/framework version details.", "Minimize technology/version disclosure where practical.", protocols=("web",), owasp=("A02:2025",), cwe=("CWE-200",), tags=("fingerprinting",), detector="server_disclosure"),

    _r("API-AUTH-001", "Operation lacks explicit security requirement", "API Authentication", "medium", "potential", "An imported protected-looking operation does not declare an explicit security requirement.", "Declare security requirements in the API specification and enforce them server-side.", protocols=("api",), owasp=("API2:2023",), tags=("openapi",), detector="openapi_security"),
    _r("API-AUTHZ-001", "Object-level authorization requires differential validation", "API Authorization", "high", "potential", "Object identifiers should be compared across authorized identities to validate BOLA resistance.", "Perform authorized differential testing and enforce ownership checks server-side.", protocols=("api",), owasp=("API1:2023",), cwe=("CWE-639",), tags=("bola", "idor"), detector="authz_matrix"),
    _r("API-AUTHZ-002", "Function-level authorization requires role comparison", "API Authorization", "high", "potential", "Privileged functions require explicit role checks.", "Enforce authorization at every privileged operation.", protocols=("api",), owasp=("API5:2023",), cwe=("CWE-862",), tags=("bfla",), detector="authz_matrix"),
    _r("API-INPUT-001", "Mass-assignment candidate", "API Input Validation", "medium", "potential", "Input schema may accept unexpected object properties.", "Reject unexpected fields or use explicit server-side field mapping.", protocols=("api",), owasp=("API3:2023",), cwe=("CWE-915",), tags=("mass-assignment",), detector="schema_additional_properties"),
    _r("API-RES-001", "Unbounded pagination/resource consumption candidate", "API Resource Management", "medium", "potential", "Page/limit controls appear weakly constrained.", "Enforce maximum page size, rate and cost controls.", protocols=("api",), owasp=("API4:2023",), tags=("dos", "pagination"), detector="resource_bounds"),
    _r("API-ERR-001", "Verbose API error schema", "API Error Handling", "medium", "potential", "The response contract exposes internal diagnostic fields.", "Use stable public error objects and keep diagnostics internal.", protocols=("api",), owasp=("API8:2023",), cwe=("CWE-209",), tags=("errors",), detector="api_error_schema"),
    _r("API-INVENTORY-001", "API inventory coverage required", "API Inventory", "low", "potential", "Versioned/shadow API inventory should be maintained and reconciled.", "Maintain a current API inventory and remove unmanaged versions/endpoints.", protocols=("api",), owasp=("API9:2023",), tags=("inventory",), detector="inventory"),
    _r("API-GQL-001", "GraphQL query depth/complexity requires enforcement", "GraphQL", "medium", "potential", "Nested queries can create high resource costs without depth/complexity controls.", "Enforce depth and query-complexity limits.", protocols=("graphql",), owasp=("API4:2023",), tags=("graphql", "dos"), detector="graphql_limits"),
    _r("API-GQL-002", "GraphQL mutation authorization review required", "GraphQL", "high", "potential", "State-changing mutations require resolver-level authorization.", "Enforce authorization in resolvers and service layers.", protocols=("graphql",), owasp=("API5:2023",), tags=("graphql", "authorization"), detector="graphql_mutation_auth"),
    _r("API-SOAP-001", "SOAP XML parser hardening required", "SOAP", "high", "potential", "XML parsers should disable unsafe external entity and DTD processing.", "Disable external entities/DTDs and enforce parser resource limits.", protocols=("soap",), owasp=("API8:2023",), cwe=("CWE-611",), tags=("soap", "xxe"), detector="soap_parser"),
    _r("API-GRPC-001", "gRPC reflection exposure requires review", "gRPC", "medium", "potential", "Reflection can disclose service and method metadata.", "Restrict reflection to trusted/admin contexts.", protocols=("grpc",), owasp=("API9:2023",), tags=("grpc", "reflection"), detector="grpc_reflection"),

    _r("AI-LLM-001", "Direct prompt-injection resilience candidate", "LLM Security", "high", "potential", "The model response indicates that instruction-boundary testing is warranted.", "Separate system/developer/user instructions and apply input/output guardrails.", protocols=("llm",), tags=("prompt-injection",), detector="llm_prompt_injection"),
    _r("AI-LLM-002", "Sensitive-information disclosure candidate", "LLM Security", "high", "potential", "Response content contains signals of sensitive or internal information disclosure.", "Apply data-loss controls, output filtering and least-privilege context.", protocols=("llm",), tags=("disclosure",), detector="llm_disclosure"),
    _r("AI-LLM-003", "Unsafe output handling candidate", "LLM Security", "high", "potential", "Model output may cross into an interpreter or browser without safe encoding.", "Treat model output as untrusted data and validate before execution/rendering.", protocols=("llm",), cwe=("CWE-79",), tags=("output",), detector="llm_output"),
    _r("AI-RAG-001", "Indirect prompt-injection candidate in retrieved content", "RAG Security", "high", "potential", "Retrieved content contains instruction-like payloads that can cross trust boundaries.", "Treat retrieved content as untrusted data and isolate instructions from retrieved text.", protocols=("rag",), tags=("rag", "indirect-injection"), detector="rag_injection"),
    _r("AI-RAG-002", "Cross-tenant retrieval isolation candidate", "RAG Security", "critical", "potential", "Retrieval metadata indicates a possible tenant boundary mismatch.", "Enforce tenant-aware retrieval filters and authorization at the retriever/data layer.", protocols=("rag",), tags=("rag", "multi-tenant"), detector="rag_tenant"),
    _r("AI-AGENT-001", "Agent tool capability exceeds declared policy", "Agent Security", "high", "potential", "A declared agent tool capability is broader than the configured allowlist.", "Apply least-privilege tool permissions and explicit policy allowlists.", protocols=("agent",), tags=("agent", "tools"), detector="agent_policy"),
    _r("AI-AGENT-002", "Agent memory/instruction boundary candidate", "Agent Security", "high", "potential", "Persistent memory or tool-returned content can influence higher-trust instructions.", "Separate memory/data from system policy and validate tool-returned instructions.", protocols=("agent",), tags=("agent", "memory"), detector="agent_boundary"),
    _r("AI-MCP-001", "MCP transport/authentication review required", "MCP Security", "medium", "potential", "Remote MCP transport and authentication configuration requires explicit review.", "Use authenticated transport and restrict remote MCP exposure.", protocols=("mcp",), tags=("mcp", "transport"), detector="mcp_transport"),

    _r("SCA-DEP-001", "Vulnerable dependency requires advisory review", "Supply Chain", "high", "confirmed", "A dependency matched an advisory record.", "Upgrade to a fixed version or apply compensating controls.", protocols=("sca",), tags=("sca", "cve"), detector="sca_advisory"),
    _r("SCA-DEP-002", "Known-exploited dependency requires prioritization", "Supply Chain", "critical", "confirmed", "A dependency is marked as known exploited by imported intelligence.", "Prioritize immediate remediation and verify exploit exposure.", protocols=("sca",), tags=("sca", "kev"), detector="sca_kev"),
    _r("SCA-DEP-003", "High probability-of-exploitation dependency", "Supply Chain", "high", "confirmed", "Imported exploit-probability intelligence indicates elevated exploit likelihood.", "Prioritize upgrade based on reachability and exposure.", protocols=("sca",), tags=("sca", "epss"), detector="sca_epss"),
    _r("SCA-LIC-001", "Dependency license requires review", "Supply Chain", "low", "potential", "The dependency license is not currently approved by the project policy.", "Review license compatibility and record an explicit allow/deny decision.", protocols=("sca",), tags=("license",), detector="sca_license"),
    _r("SCA-SUPPLY-001", "Suspicious dependency naming indicator", "Supply Chain", "medium", "potential", "Dependency name resembles a common package closely enough to warrant supply-chain review.", "Verify package provenance, publisher and repository integrity.", protocols=("sca",), tags=("typosquatting",), detector="sca_name_similarity"),
    _r("SCA-SBOM-001", "SBOM drift detected", "Supply Chain", "medium", "confirmed", "Current dependency inventory differs from the expected SBOM baseline.", "Review added/changed components and update the approved SBOM.", protocols=("sca",), tags=("sbom", "drift"), detector="sca_sbom_diff"),
]

# Additional generic rule families expand coverage without hard-coding exploitation logic.
_EXTRA = []
for i, (family, title, severity, cwe, tag) in enumerate([
    ("Authentication", "Password policy requires application-context review", "medium", "CWE-521", "auth"),
    ("Authentication", "MFA enforcement requires privileged-path review", "high", "CWE-308", "mfa"),
    ("Session Management", "Session invalidation requires logout/revocation verification", "medium", "CWE-613", "session"),
    ("Authorization", "Privilege boundary requires negative-path validation", "high", "CWE-862", "authorization"),
    ("Configuration", "Debug-mode exposure requires deployment review", "medium", "CWE-489", "debug"),
    ("Configuration", "Default credential indicator requires validation", "high", "CWE-1391", "credentials"),
    ("Transport", "TLS configuration requires modern-policy review", "medium", "CWE-319", "tls"),
    ("Transport", "Cleartext redirect chain requires review", "medium", "CWE-319", "tls"),
    ("Input Validation", "Unexpected content type requires validation", "low", "CWE-20", "validation"),
    ("Input Validation", "Oversized request handling requires resource-limit validation", "medium", "CWE-400", "resource"),
    ("Business Logic", "Multi-step workflow requires state transition validation", "high", "CWE-841", "business-logic"),
    ("Business Logic", "Replay-sensitive action requires idempotency validation", "medium", "CWE-294", "replay"),
    ("Business Logic", "Concurrency-sensitive action requires race-condition review", "high", "CWE-362", "race"),
    ("Error Handling", "Consistent authorization errors require review", "low", "CWE-209", "errors"),
    ("Data Exposure", "Sensitive response fields require minimization review", "medium", "CWE-200", "exposure"),
    ("Data Exposure", "PII in client response requires minimization review", "medium", "CWE-359", "pii"),
    ("File Handling", "Upload content-type validation requires review", "high", "CWE-434", "upload"),
    ("File Handling", "Archive extraction path handling requires review", "high", "CWE-22", "archive"),
    ("Redirect", "Open redirect candidate requires destination validation", "medium", "CWE-601", "redirect"),
    ("Caching", "Sensitive response caching requires review", "medium", "CWE-525", "cache"),
    ("Headers", "Permissions-Policy requires review", "low", "CWE-16", "headers"),
    ("Headers", "COOP/COEP/CORP isolation requires review", "low", "CWE-16", "headers"),
    ("API", "Version sunset policy requires inventory review", "low", "CWE-16", "api"),
    ("API", "Rate-limit policy requires authenticated endpoint review", "medium", "CWE-770", "rate-limit"),
    ("API", "Idempotency support requires mutation review", "medium", "CWE-362", "idempotency"),
    ("GraphQL", "GraphQL introspection exposure requires environment review", "low", "CWE-200", "graphql"),
    ("GraphQL", "GraphQL batching requires resource controls", "medium", "CWE-400", "graphql"),
    ("SOAP", "SOAP action allowlisting requires review", "medium", "CWE-20", "soap"),
    ("gRPC", "gRPC metadata authorization requires review", "high", "CWE-862", "grpc"),
    ("LLM Security", "Model tool invocation requires authorization boundary review", "high", "CWE-862", "agent"),
    ("LLM Security", "Model output schema enforcement requires review", "medium", "CWE-20", "output"),
    ("RAG Security", "Document provenance requires trust classification", "medium", "CWE-345", "rag"),
    ("RAG Security", "Retriever filter enforcement requires tenant validation", "critical", "CWE-639", "rag"),
    ("Agent Security", "Agent autonomy requires explicit action budget", "high", "CWE-269", "agent"),
    ("Agent Security", "Agent identity delegation requires scope review", "high", "CWE-269", "agent"),
    ("MCP Security", "MCP tool schema requires input validation", "medium", "CWE-20", "mcp"),
    ("MCP Security", "MCP server trust boundary requires provenance review", "high", "CWE-345", "mcp"),
    ("SCA", "Transitive dependency requires review", "medium", "CWE-1104", "sca"),
    ("SCA", "Development dependency in production image requires review", "medium", "CWE-1104", "sca"),
    ("SCA", "Unpinned dependency requires reproducibility review", "low", "CWE-1104", "sca"),
    ("SCA", "Abandoned dependency indicator requires maintenance review", "medium", "CWE-1104", "sca"),
    ("SCA", "Repository provenance mismatch requires review", "high", "CWE-345", "sca"),
]):
    n = i + 1
    _EXTRA.append(_r(
        f"RULE-{family.upper().replace(' ', '-')[:8]}-{n:03d}",
        title,
        family,
        severity,
        "potential",
        f"{title}. This rule provides a deterministic review point in the security pipeline.",
        "Validate the condition in application context and apply the least-privilege remediation appropriate to the deployment.",
        protocols=("web", "api", "llm", "rag", "agent", "mcp", "sca"),
        cwe=(cwe,),
        tags=(tag,),
        detector="context_review",
    ))

RULE_CATALOG: tuple[RuleDefinition, ...] = tuple(_BASE + _EXTRA)
RULE_INDEX = {rule.key: rule for rule in RULE_CATALOG}


def rule_catalog_summary() -> dict[str, object]:
    families: dict[str, int] = {}
    severity: dict[str, int] = {}
    for rule in RULE_CATALOG:
        families[rule.family] = families.get(rule.family, 0) + 1
        severity[rule.severity] = severity.get(rule.severity, 0) + 1
    return {"total": len(RULE_CATALOG), "families": families, "severity": severity}

from .library import (  # noqa: E402
    detect_security_header_misconfig, detect_http_transport, detect_cache_control,
    detect_method_exposure, detect_open_redirect, detect_security_sensitive_response,
    detect_auth_session, detect_api_schema, detect_api_auth, detect_graphql,
    detect_soap_grpc, detect_ai, detect_sca,
)

# Wave 11 actual validator-backed rules. The RuleEngine maps these detector names
# to executable implementations rather than catalog-only context flags.
WAVE11 = [
    _r("WEB-HDR-004", "Missing Permissions-Policy", "Security Headers", "low", "confirmed", "Permissions-Policy is absent.", "Define an application-appropriate Permissions-Policy.", protocols=("web",), owasp=("A02:2025",), detector="security_header_misconfig"),
    _r("WEB-HDR-005", "Missing Cross-Origin-Opener-Policy", "Security Headers", "low", "confirmed", "COOP is absent.", "Define COOP where cross-origin isolation or window-opener protection is required.", protocols=("web",), owasp=("A02:2025",), detector="security_header_misconfig"),
    _r("WEB-HDR-006", "Missing Cross-Origin-Resource-Policy", "Security Headers", "low", "confirmed", "CORP is absent.", "Define CORP when the application's cross-origin resource policy requires it.", protocols=("web",), owasp=("A02:2025",), detector="security_header_misconfig"),
    _r("WEB-HDR-007", "Missing Cross-Origin-Embedder-Policy", "Security Headers", "low", "confirmed", "COEP is absent.", "Define COEP when cross-origin isolation is required.", protocols=("web",), owasp=("A02:2025",), detector="security_header_misconfig"),
    _r("WEB-TRANS-001", "Plain HTTP target", "Transport", "medium", "confirmed", "The target is accessed over HTTP rather than HTTPS.", "Serve sensitive application traffic exclusively over HTTPS.", protocols=("web",), cwe=("CWE-319",), owasp=("A04:2025",), detector="http_transport"),
    _r("WEB-CACHE-001", "Potentially sensitive content lacks restrictive cache policy", "Caching", "medium", "potential", "HTML/JSON content does not expose no-store/private cache semantics.", "Review whether sensitive responses require no-store or private caching.", protocols=("web", "api"), owasp=("A02:2025",), detector="cache_control"),
    _r("WEB-METHOD-001", "Risky HTTP methods advertised", "HTTP Methods", "medium", "confirmed", "The Allow header advertises state-changing or uncommon methods.", "Disable unnecessary methods and protect state-changing operations.", protocols=("web", "api"), owasp=("A05:2025",), detector="method_exposure"),
    _r("WEB-METHOD-002", "TRACE method advertised", "HTTP Methods", "low", "confirmed", "TRACE is advertised in Allow.", "Disable TRACE unless explicitly required.", protocols=("web",), owasp=("A02:2025",), detector="method_exposure"),
    _r("WEB-REDIR-001", "Potential open redirect", "Redirects", "medium", "potential", "A redirect-like parameter is combined with redirect behavior.", "Allowlist redirect destinations and use relative paths where possible.", protocols=("web", "api"), cwe=("CWE-601",), detector="open_redirect"),
    _r("WEB-DATA-001", "Potential secret/token data disclosure", "Data Exposure", "high", "potential", "Response contains fields that resemble secrets or tokens.", "Avoid returning credentials/secrets and minimize sensitive response data.", protocols=("web", "api"), cwe=("CWE-200",), owasp=("A01:2025",), detector="security_sensitive_response"),
    _r("WEB-DATA-002", "Potential internal diagnostic data disclosure", "Data Exposure", "medium", "potential", "Response contains internal diagnostic markers.", "Remove debug/internal metadata from external responses.", protocols=("web", "api"), cwe=("CWE-209",), owasp=("A10:2025",), detector="security_sensitive_response"),
    _r("WEB-DATA-003", "Potential PII/financial data disclosure", "Data Exposure", "high", "potential", "Response contains markers associated with sensitive personal/financial data.", "Minimize sensitive data and enforce authorization before disclosure.", protocols=("web", "api"), cwe=("CWE-359",), detector="security_sensitive_response"),
    _r("WEB-AUTH-001", "Unauthorized response lacks authentication challenge", "Authentication", "low", "potential", "401/403 responses lack WWW-Authenticate signaling.", "Review authentication challenge behavior and API contract.", protocols=("web", "api"), owasp=("A07:2025",), detector="auth_session"),
    _r("WEB-AUTH-002", "Login response lacks no-store caching control", "Authentication", "medium", "potential", "A login endpoint does not clearly prohibit caching.", "Set Cache-Control: no-store on authentication responses where appropriate.", protocols=("web",), owasp=("A07:2025",), detector="auth_session"),
    _r("API-SCHEMA-003", "Unconstrained request body", "API Input Validation", "medium", "potential", "Request body schema is marked unconstrained.", "Define explicit object schemas and reject unexpected structures.", protocols=("api",), owasp=("API3:2023",), detector="api_schema"),
    _r("API-SCHEMA-004", "Unbounded numeric input", "API Input Validation", "medium", "potential", "Numeric input lacks an upper bound in the supplied schema metadata.", "Apply sensible min/max constraints.", protocols=("api",), owasp=("API3:2023",), detector="api_schema"),
    _r("API-SCHEMA-005", "Unpatterned string input", "API Input Validation", "low", "potential", "String input lacks a pattern in a policy requiring one.", "Add format/pattern validation where business context permits.", protocols=("api",), owasp=("API3:2023",), detector="api_schema"),
    _r("API-AUTH-002", "Anonymous access to protected operation", "API Authentication", "critical", "confirmed", "An authorized test observed anonymous access to a protected operation.", "Enforce authentication server-side on protected operations.", protocols=("api",), owasp=("API2:2023",), detector="api_auth"),
    _r("API-AUTHZ-003", "Cross-tenant object access observed", "API Authorization", "critical", "confirmed", "An authorized differential test observed cross-tenant access.", "Enforce tenant/object ownership checks at every access layer.", protocols=("api",), owasp=("API1:2023",), cwe=("CWE-639",), detector="api_auth"),
    _r("API-AUTHZ-004", "Privileged action accessible to lower role", "API Authorization", "critical", "confirmed", "An authorized role-differential test observed a privileged action from a lower role.", "Enforce function-level authorization server-side.", protocols=("api",), owasp=("API5:2023",), cwe=("CWE-862",), detector="api_auth"),
    _r("API-RATE-001", "No observed rate-limit policy", "API Resource Management", "medium", "potential", "Authorized metadata does not show rate limiting on a cost-sensitive endpoint.", "Apply per-principal and resource-aware rate limits.", protocols=("api",), owasp=("API4:2023",), detector="api_auth"),
    _r("API-GQL-003", "Public GraphQL introspection", "GraphQL", "medium", "confirmed", "GraphQL introspection is publicly exposed.", "Restrict introspection in production where it is not required.", protocols=("api",), owasp=("API9:2023",), detector="graphql"),
    _r("API-GQL-004", "No observed GraphQL depth limit", "GraphQL", "medium", "potential", "No depth limit was observed in supplied metadata.", "Enforce query depth limits.", protocols=("api",), owasp=("API4:2023",), detector="graphql"),
    _r("API-GQL-005", "No observed GraphQL batching/alias limit", "GraphQL", "medium", "potential", "No alias/batching limit was observed.", "Constrain aliases, batching and query cost.", protocols=("api",), owasp=("API4:2023",), detector="graphql"),
    _r("API-SOAP-002", "XML external entities enabled", "SOAP", "critical", "confirmed", "Authorized metadata indicates external entity processing is enabled.", "Disable DTD and external entity resolution.", protocols=("api",), cwe=("CWE-611",), detector="soap_grpc"),
    _r("API-SOAP-003", "XML entity expansion limit absent", "SOAP", "medium", "potential", "No entity expansion/resource limit was observed.", "Apply parser depth and entity expansion limits.", protocols=("api",), detector="soap_grpc"),
    _r("API-GRPC-002", "gRPC plaintext transport", "gRPC", "high", "confirmed", "Authorized metadata indicates plaintext gRPC transport.", "Use TLS for gRPC in production.", protocols=("api",), owasp=("API2:2023",), cwe=("CWE-319",), detector="soap_grpc"),
    _r("API-GRPC-003", "Public gRPC reflection", "gRPC", "medium", "confirmed", "gRPC reflection is publicly exposed.", "Restrict reflection to trusted/admin contexts.", protocols=("api",), detector="soap_grpc"),
    _r("AI-LLM-001", "Prompt injection behavior observed", "LLM Security", "high", "high", "An authorized red-team campaign observed instruction override behavior.", "Apply instruction hierarchy, input isolation and output/tool guardrails.", protocols=("ai",), detector="ai"),
    _r("AI-LLM-002", "System instruction disclosure", "LLM Security", "high", "high", "System-level instruction disclosure was observed.", "Minimize sensitive system instructions and enforce output filtering.", protocols=("ai",), detector="ai"),
    _r("AI-LLM-003", "Sensitive data disclosure", "LLM Security", "critical", "high", "Sensitive data disclosure was observed in an authorized campaign.", "Enforce data loss prevention, retrieval authorization and output controls.", protocols=("ai",), detector="ai"),
    _r("AI-LLM-004", "Unsafe executable output path", "LLM Security", "critical", "high", "Model output reaches an executable action path without adequate controls.", "Require policy validation and human/agent authorization before execution.", protocols=("ai",), detector="ai"),
    _r("AI-RAG-001", "Indirect prompt injection in retrieved content", "RAG Security", "high", "high", "Retrieved content influenced model behavior as instructions.", "Treat retrieved content as untrusted data and isolate instructions.", protocols=("ai",), detector="ai"),
    _r("AI-RAG-002", "Cross-tenant retrieval observed", "RAG Security", "critical", "confirmed", "An authorized comparison observed retrieval across tenant boundaries.", "Enforce tenant-aware retrieval authorization at the data layer.", protocols=("ai",), detector="ai"),
    _r("AI-AGENT-001", "Excessive agent tool privilege", "Agent Security", "critical", "high", "Agent tool capability exceeds the declared task boundary.", "Apply least-privilege tool scopes and explicit policy checks.", protocols=("ai",), detector="ai"),
    _r("AI-AGENT-002", "Agent memory poisoning observed", "Agent Security", "high", "high", "Untrusted content persisted as agent memory/instructions.", "Sanitize memory writes and separate data from executable instructions.", protocols=("ai",), detector="ai"),
    _r("AI-MCP-001", "Untrusted MCP transport configuration", "MCP Security", "high", "potential", "Configured MCP transport does not meet the organization's trust boundary.", "Use authenticated, integrity-protected transports and explicit server allowlists.", protocols=("ai",), detector="ai"),
    _r("SCA-001", "Dependency advisory match", "SCA", "high", "confirmed", "Dependency matches a known vulnerability advisory.", "Upgrade/replace the affected dependency and validate reachability.", protocols=("sca",), detector="sca"),
    _r("SCA-002", "Known-exploited dependency", "SCA", "critical", "high", "Dependency is flagged as known exploited in supplied intelligence.", "Prioritize immediate remediation and compensating controls.", protocols=("sca",), detector="sca"),
    _r("SCA-003", "High EPSS exploitation probability", "SCA", "high", "confirmed", "Dependency vulnerability has high EPSS in supplied intelligence.", "Prioritize remediation based on exploit probability and exposure.", protocols=("sca",), detector="sca"),
    _r("SCA-004", "Reachable vulnerable dependency", "SCA", "critical", "high", "Vulnerable dependency is reachable from application code.", "Upgrade or remove the dependency and verify the vulnerable path is no longer reachable.", protocols=("sca",), detector="sca"),
    _r("SCA-005", "License policy conflict", "Supply Chain", "medium", "confirmed", "Dependency license conflicts with configured policy.", "Replace, remediate or formally approve the dependency license.", protocols=("sca",), detector="sca"),
    _r("SCA-006", "Potential dependency typosquatting", "Supply Chain", "high", "potential", "Dependency name similarity suggests a possible typosquatting risk.", "Verify package provenance, publisher and integrity before use.", protocols=("sca",), detector="sca"),
    _r("SCA-007", "SBOM dependency drift", "Supply Chain", "medium", "confirmed", "Dependency inventory differs from the approved SBOM baseline.", "Review and approve dependency changes through the software supply-chain process.", protocols=("sca",), detector="sca"),
]

# Wave 14: reusable injection/validation rules.
_WAVE14 = [
    _r("INJ-SQL-001", "SQL injection error/correlation indicator", "Injection", "high", "potential", "Controlled input variation correlates with a database error signature.", "Use parameterized queries, strict input validation and safe error handling.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-89",), tags=("sqli", "validation"), detector="inj_evaluate"),
    _r("INJ-SQL-002", "SQL injection differential behavior indicator", "Injection", "critical", "potential", "Authorized differential analysis indicates database-dependent response behavior.", "Use parameterized queries and review query construction and authorization boundaries.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-89",), tags=("sqli", "differential"), detector="inj_evaluate"),
    _r("INJ-SSRF-001", "SSRF server-side fetch candidate", "Server-Side Request", "high", "potential", "A request parameter appears capable of controlling a server-side fetch operation.", "Allowlist destinations and block private, loopback, link-local and metadata ranges.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-918",), tags=("ssrf", "oast-ready"), detector="inj_evaluate"),
    _r("INJ-SSRF-002", "SSRF callback correlation observed", "Server-Side Request", "critical", "confirmed", "A customer-controlled OAST correlation token was observed in an authorized callback.", "Restrict server-side destinations and enforce network egress policy.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-918",), tags=("ssrf", "oast"), detector="inj_evaluate"),
    _r("INJ-SSTI-001", "Server-side template injection indicator", "Injection", "high", "potential", "A controlled template probe correlated with template-engine error behavior.", "Avoid evaluating user-controlled templates and use context-safe rendering APIs.", protocols=("web", "api"), owasp=("A05:2025",), cwe=("CWE-1336",), tags=("ssti", "template"), detector="inj_evaluate"),
    _r("INJ-XXE-001", "XML external entity processing enabled", "Injection", "critical", "confirmed", "Authorized parser metadata indicates external entity processing is enabled.", "Disable DTD and external entity resolution and apply secure XML parser settings.", protocols=("web", "api"), owasp=("A05:2025", "A02:2025"), cwe=("CWE-611",), tags=("xxe", "xml"), detector="inj_evaluate"),
    _r("INJ-LDAP-001", "LDAP injection/error indicator", "Injection", "high", "potential", "An LDAP parser/error indicator was observed during authorized validation.", "Use parameterized LDAP APIs and strict input validation.", protocols=("web", "api"), cwe=("CWE-90",), tags=("ldap", "injection"), detector="inj_evaluate"),
    _r("INJ-XPATH-001", "XPath injection/error indicator", "Injection", "high", "potential", "An XPath parser/error indicator was observed during authorized validation.", "Use parameterized XPath APIs and validate input before query construction.", protocols=("web", "api"), cwe=("CWE-643",), tags=("xpath", "injection"), detector="inj_evaluate"),
    _r("INJ-CRLF-001", "HTTP response header injection indicator", "Injection", "high", "potential", "Response behavior indicates user-controlled header boundary manipulation.", "Reject CR/LF control characters and construct headers through safe framework APIs.", protocols=("web", "api"), cwe=("CWE-113",), tags=("crlf", "headers"), detector="inj_evaluate"),
]

# Wave 11 definitions replace earlier catalog-only versions with executable detectors.
_WAVE11_KEYS = {r.key for r in WAVE11}
_BASE = [r for r in _BASE if r.key not in _WAVE11_KEYS]
_BASE.extend(WAVE11)

# Rebuild exported catalog/index after all wave-specific rules are loaded.
RULE_INDEX = {}
# Wave 14 definitions are executable through the shared injection detector.
_WAVE14_KEYS = {r.key for r in _WAVE14}
_BASE = [r for r in _BASE if r.key not in _WAVE14_KEYS]
_BASE.extend(_WAVE14)

RULE_CATALOG = tuple(_BASE + _EXTRA)
RULE_INDEX = {rule.key: rule for rule in RULE_CATALOG}

# Wave 17 modular rule pack. Imported here after the base catalog is defined.
try:
    from .wave17_catalog import WAVE17
except ImportError:  # pragma: no cover - package import guard
    WAVE17 = []
RULE_CATALOG = tuple(list(RULE_CATALOG) + list(WAVE17))
RULE_INDEX = {rule.key: rule for rule in RULE_CATALOG}
