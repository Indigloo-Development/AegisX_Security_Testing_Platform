from __future__ import annotations

from .models import Evidence, RuleDefinition, RuleFinding, ScanContext


def _finding(rule: RuleDefinition, ctx: ScanContext, message: str, kind: str = "analysis", location: str | None = None) -> RuleFinding:
    return RuleFinding(
        rule_key=rule.key,
        title=rule.title,
        family=rule.family,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        remediation=rule.remediation,
        evidence=(Evidence(kind, location or ctx.url, message),),
        owasp=rule.owasp,
        cwe=rule.cwe,
        tags=rule.tags,
        location=location or ctx.url,
    )


def detect_security_header_misconfig(ctx: ScanContext, rule: RuleDefinition):
    h = {k.lower(): v.strip() for k, v in ctx.headers.items()}
    mapping = {
        "WEB-HDR-004": ("permissions-policy", "missing Permissions-Policy"),
        "WEB-HDR-005": ("cross-origin-opener-policy", "missing COOP"),
        "WEB-HDR-006": ("cross-origin-resource-policy", "missing CORP"),
        "WEB-HDR-007": ("cross-origin-embedder-policy", "missing COEP"),
    }
    header, msg = mapping[rule.key]
    if header not in h:
        return [_finding(rule, ctx, msg, "header")]
    return []


def detect_http_transport(ctx: ScanContext, rule: RuleDefinition):
    if ctx.url.lower().startswith("http://"):
        return [_finding(rule, ctx, "target URL is plain HTTP", "url")]
    return []


def detect_cache_control(ctx: ScanContext, rule: RuleDefinition):
    cc = ctx.headers.get("cache-control", "").lower()
    ct = ctx.headers.get("content-type", "").lower()
    if any(x in ct for x in ("json", "text/html")) and not any(x in cc for x in ("no-store", "private")):
        return [_finding(rule, ctx, f"cache-control='{cc or '<missing>'}' for potentially sensitive content", "header")]
    return []


def detect_method_exposure(ctx: ScanContext, rule: RuleDefinition):
    allow = ctx.headers.get("allow", "").upper()
    risky = {"PUT", "PATCH", "DELETE", "TRACE"}
    methods = risky.intersection({x.strip() for x in allow.split(",")})
    if methods and rule.key == "WEB-METHOD-001":
        return [_finding(rule, ctx, f"Allow header advertises risky methods: {', '.join(sorted(methods))}", "header")]
    if "TRACE" in allow and rule.key == "WEB-METHOD-002":
        return [_finding(rule, ctx, "TRACE is advertised in Allow header", "header")]
    return []


def detect_open_redirect(ctx: ScanContext, rule: RuleDefinition):
    names = {str(p.get("name", "")).lower() for p in ctx.parameters}
    body = ctx.body.lower()
    if names.intersection({"redirect", "url", "next", "return", "returnurl", "continue"}) and (ctx.status_code in {301, 302, 303, 307, 308} or "location:" in body):
        return [_finding(rule, ctx, "redirect-like parameter combined with redirect behavior", "parameter")]
    return []


def detect_security_sensitive_response(ctx: ScanContext, rule: RuleDefinition):
    b = ctx.body.lower()
    markers = {
        "WEB-DATA-001": ("password", "secret", "api_key", "access_token"),
        "WEB-DATA-002": ("stack_trace", "traceback", "debug", "internal_hostname"),
        "WEB-DATA-003": ("ssn", "credit_card", "national_id", "date_of_birth"),
    }
    hit = next((m for m in markers[rule.key] if m in b), None)
    if hit:
        return [_finding(rule, ctx, f"sensitive-data indicator '{hit}' present in response", "body")]
    return []


def detect_auth_session(ctx: ScanContext, rule: RuleDefinition):
    h = {k.lower(): v for k, v in ctx.headers.items()}
    if rule.key == "WEB-AUTH-001" and ctx.status_code in {401, 403} and "www-authenticate" not in h:
        return [_finding(rule, ctx, "401/403 response does not advertise WWW-Authenticate", "header")]
    if rule.key == "WEB-AUTH-002" and ctx.method.upper() == "POST" and not h.get("cache-control", "").lower().find("no-store") >= 0 and "login" in ctx.url.lower():
        return [_finding(rule, ctx, "login endpoint lacks explicit no-store cache directive", "header")]
    return []


def detect_api_schema(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    if rule.key == "API-SCHEMA-003" and m.get("request_body_schema") == "unconstrained":
        return [_finding(rule, ctx, "request body schema is unconstrained", "metadata")]
    if rule.key == "API-SCHEMA-004" and m.get("integer_max") is None:
        return [_finding(rule, ctx, "integer input lacks an upper bound", "metadata")]
    if rule.key == "API-SCHEMA-005" and m.get("string_pattern") is None:
        return [_finding(rule, ctx, "string input lacks a pattern constraint in a policy requiring one", "metadata")]
    return []


def detect_api_auth(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    key = rule.key
    if key == "API-AUTH-002" and m.get("anonymous_access") is True:
        return [_finding(rule, ctx, "protected operation accepted anonymous access in authorized test metadata", "metadata")]
    if key == "API-AUTHZ-003" and m.get("cross_tenant_read") is True:
        return [_finding(rule, ctx, "cross-tenant read observed in authorized differential test", "metadata")]
    if key == "API-AUTHZ-004" and m.get("privileged_action_low_role") is True:
        return [_finding(rule, ctx, "privileged action was observable from a lower-privilege role", "metadata")]
    if key == "API-RATE-001" and m.get("rate_limit_absent") is True:
        return [_finding(rule, ctx, "rate-limit policy not observed in authorized test metadata", "metadata")]
    return []


def detect_graphql(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    if rule.key == "API-GQL-003" and m.get("introspection_public") is True:
        return [_finding(rule, ctx, "GraphQL introspection is publicly exposed", "metadata")]
    if rule.key == "API-GQL-004" and m.get("query_depth_limit") is None:
        return [_finding(rule, ctx, "no query depth limit was observed", "metadata")]
    if rule.key == "API-GQL-005" and m.get("alias_batching_limit") is None:
        return [_finding(rule, ctx, "no alias/batching limit was observed", "metadata")]
    return []


def detect_soap_grpc(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    if rule.key == "API-SOAP-002" and m.get("external_entities_enabled") is True:
        return [_finding(rule, ctx, "external entity processing is enabled", "metadata")]
    if rule.key == "API-SOAP-003" and m.get("entity_expansion_limit") is None:
        return [_finding(rule, ctx, "XML entity expansion limit is not defined", "metadata")]
    if rule.key == "API-GRPC-002" and m.get("plaintext_transport") is True:
        return [_finding(rule, ctx, "gRPC endpoint uses plaintext transport", "metadata")]
    if rule.key == "API-GRPC-003" and m.get("reflection_public") is True:
        return [_finding(rule, ctx, "gRPC reflection is publicly exposed", "metadata")]
    return []


def detect_ai(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    if rule.key == "AI-LLM-001" and m.get("prompt_injection_success") is True:
        return [_finding(rule, ctx, "authorized campaign observed instruction override behavior", "metadata")]
    if rule.key == "AI-LLM-002" and m.get("system_prompt_disclosed") is True:
        return [_finding(rule, ctx, "system instruction disclosure indicator observed", "metadata")]
    if rule.key == "AI-LLM-003" and m.get("sensitive_data_disclosed") is True:
        return [_finding(rule, ctx, "sensitive data disclosure indicator observed", "metadata")]
    if rule.key == "AI-LLM-004" and m.get("unsafe_output_executable") is True:
        return [_finding(rule, ctx, "unsafe executable output path observed", "metadata")]
    if rule.key == "AI-RAG-001" and m.get("document_injection_observed") is True:
        return [_finding(rule, ctx, "indirect instruction in retrieved content influenced model behavior", "metadata")]
    if rule.key == "AI-RAG-002" and m.get("cross_tenant_retrieval") is True:
        return [_finding(rule, ctx, "cross-tenant retrieval observed in authorized comparison", "metadata")]
    if rule.key == "AI-AGENT-001" and m.get("tool_privilege_excessive") is True:
        return [_finding(rule, ctx, "agent tool capability exceeds declared task boundary", "metadata")]
    if rule.key == "AI-AGENT-002" and m.get("memory_poisoning_observed") is True:
        return [_finding(rule, ctx, "persistent memory accepted untrusted instruction content", "metadata")]
    if rule.key == "AI-MCP-001" and m.get("mcp_server_untrusted_transport") is True:
        return [_finding(rule, ctx, "MCP server uses an untrusted transport configuration", "metadata")]
    return []


def detect_sca(ctx: ScanContext, rule: RuleDefinition):
    m = ctx.metadata
    if rule.key == "SCA-001" and m.get("cve_id"):
        return [_finding(rule, ctx, f"advisory matched: {m['cve_id']}", "metadata")]
    if rule.key == "SCA-002" and m.get("kev") is True:
        return [_finding(rule, ctx, "dependency vulnerability is present in known-exploited catalog", "metadata")]
    if rule.key == "SCA-003" and m.get("epss") is not None and float(m["epss"]) >= 0.7:
        return [_finding(rule, ctx, f"EPSS={m['epss']}", "metadata")]
    if rule.key == "SCA-004" and m.get("reachable") is True:
        return [_finding(rule, ctx, "vulnerable dependency is reachable from application usage", "metadata")]
    if rule.key == "SCA-005" and m.get("license_risk") is True:
        return [_finding(rule, ctx, "dependency license conflicts with configured policy", "metadata")]
    if rule.key == "SCA-006" and m.get("name_similarity") is True:
        return [_finding(rule, ctx, "package name similarity indicates possible typosquatting", "metadata")]
    if rule.key == "SCA-007" and m.get("sbom_drift") is True:
        return [_finding(rule, ctx, "SBOM drift detected", "metadata")]
    return []
