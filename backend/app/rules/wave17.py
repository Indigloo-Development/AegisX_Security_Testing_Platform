from __future__ import annotations

from .models import Evidence, RuleDefinition, RuleFinding, ScanContext


def _f(rule: RuleDefinition, ctx: ScanContext, message: str, kind: str = "analysis", location: str | None = None) -> RuleFinding:
    loc = location or ctx.url
    return RuleFinding(
        rule_key=rule.key, title=rule.title, family=rule.family,
        severity=rule.severity, confidence=rule.confidence,
        description=rule.description, remediation=rule.remediation,
        evidence=(Evidence(kind, loc, message[:800]),),
        owasp=rule.owasp, cwe=rule.cwe, tags=rule.tags, location=loc,
    )


def detect(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
    m = {str(k).lower(): v for k, v in ctx.metadata.items()}
    b = (ctx.body or "").lower()
    h = {str(k).lower(): str(v).lower() for k, v in ctx.headers.items()}
    key = rule.key

    # Web-side validators. These are evidence/metadata driven and do not execute exploits.
    web_flags = {
        "WEB-XSS-001": ("xss_reflection_context", "reflection"),
        "WEB-XSS-002": ("dom_xss_sink_observed", "dom"),
        "WEB-XSS-003": ("dom_source_to_sink", "dom"),
        "WEB-SQL-001": ("sql_error_indicator", "body"),
        "WEB-SQL-002": ("sql_differential", "response"),
        "WEB-SSRF-001": ("ssrf_candidate", "metadata"),
        "WEB-SSRF-002": ("oast_callback_observed", "oast"),
        "WEB-SSTI-001": ("template_error_indicator", "body"),
        "WEB-XXE-001": ("external_entity_processing", "metadata"),
        "WEB-PATH-001": ("path_traversal_error_indicator", "body"),
        "WEB-CMD-001": ("command_error_indicator", "body"),
        "WEB-CSRF-001": ("state_change_without_csrf_control", "workflow"),
        "WEB-UPLOAD-001": ("unrestricted_upload_type", "metadata"),
        "WEB-UPLOAD-002": ("upload_path_executable", "metadata"),
        "WEB-DESER-001": ("unsafe_deserialization_indicator", "metadata"),
        "WEB-REDIR-002": ("external_location_controlled", "header"),
        "WEB-CRLF-001": ("header_injection_indicator", "header"),
        "WEB-ERROR-001": ("stacktrace_exposed", "body"),
    }
    if key in web_flags:
        flag, kind = web_flags[key]
        if m.get(flag) is True:
            return [_f(rule, ctx, f"authorized evidence flag '{flag}' was observed", kind)]
        return []

    # API-side authorization and abuse indicators.
    api_flags = {
        "API-BOLA-001": "object_access_mismatch",
        "API-BOLA-002": "cross_tenant_object_read",
        "API-BFLA-001": "function_access_mismatch",
        "API-BFLA-002": "privileged_method_lower_role",
        "API-BOPLA-001": "sensitive_field_overexposed",
        "API-BOPLA-002": "mass_assignment_observed",
        "API-RATE-002": "rate_limit_bypass_observed",
        "API-RESOURCE-001": "resource_exhaustion_candidate",
        "API-INVENTORY-001": "shadow_api_observed",
        "API-INVENTORY-002": "deprecated_api_exposed",
        "API-SSRF-001": "api_ssrf_candidate",
        "API-ERR-001": "sensitive_error_schema",
    }
    if key in api_flags:
        flag = api_flags[key]
        if m.get(flag) is True:
            return [_f(rule, ctx, f"authorized API analysis observed '{flag}'", "metadata")]
        return []

    # GraphQL/SOAP/gRPC deep checks.
    protocol_flags = {
        "GQL-AUTH-001": "resolver_auth_missing",
        "GQL-AUTH-002": "field_auth_missing",
        "GQL-DOSE-001": "query_cost_unbounded",
        "GQL-DOSE-002": "batching_unbounded",
        "SOAP-SEC-001": "ws_security_missing",
        "SOAP-SEC-002": "schema_validation_disabled",
        "GRPC-AUTH-001": "grpc_method_auth_missing",
        "GRPC-TRANS-001": "grpc_tls_disabled",
        "GRPC-REFL-001": "grpc_reflection_public",
    }
    if key in protocol_flags:
        flag = protocol_flags[key]
        if m.get(flag) is True:
            return [_f(rule, ctx, f"protocol analysis observed '{flag}'", "metadata")]
        return []

    # Authentication/session-related web/API correlation.
    auth_flags = {
        "AUTH-MFA-001": "mfa_not_required",
        "AUTH-MFA-002": "mfa_bypass_observed",
        "AUTH-RESET-001": "password_reset_token_not_rotated",
        "AUTH-RESET-002": "password_reset_reusable",
        "AUTH-SESSION-001": "session_fixation_indicator",
        "AUTH-SESSION-002": "logout_session_reusable",
        "AUTH-OAUTH-001": "oauth_redirect_uri_overbroad",
        "AUTH-OAUTH-002": "oauth_state_missing",
        "AUTH-OAUTH-003": "oauth_pkce_missing",
        "AUTH-OIDC-001": "oidc_nonce_missing",
    }
    if key in auth_flags:
        flag = auth_flags[key]
        if m.get(flag) is True:
            return [_f(rule, ctx, f"authorized authentication analysis observed '{flag}'", "metadata")]
        return []

    # Business-logic and state-machine observations.
    logic_flags = {
        "BL-STATE-001": "invalid_state_transition",
        "BL-STATE-002": "prerequisite_bypass",
        "BL-PRICE-001": "negative_or_zero_price_accepted",
        "BL-REPLAY-001": "replay_token_accepted",
        "BL-RACE-001": "concurrent_state_conflict",
    }
    if key in logic_flags:
        flag = logic_flags[key]
        if m.get(flag) is True:
            return [_f(rule, ctx, f"workflow analysis observed '{flag}'", "workflow")]
        return []

    # Defensive response heuristics for common weak patterns.
    if key == "WEB-XSS-004":
        if m.get("unsafe_inline_script") is True or "javascript:" in b:
            return [_f(rule, ctx, "response contains executable inline/javascript content indicator", "body")]
    if key == "WEB-CACHE-002":
        cc = h.get("cache-control", "")
        if ("set-cookie" in h or m.get("sensitive_response") is True) and "no-store" not in cc:
            return [_f(rule, ctx, f"sensitive response lacks no-store: cache-control='{cc or '<missing>'}'", "header")]
    if key == "WEB-MIXED-001":
        if ctx.url.lower().startswith("https://") and ("src=\"http://" in b or "href=\"http://" in b):
            return [_f(rule, ctx, "HTTPS page contains HTTP resource references", "body")]
    return []
