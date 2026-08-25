from __future__ import annotations

from collections import defaultdict
from typing import Callable, Iterable, Sequence

from .catalog import RULE_INDEX
from .models import Evidence, RuleDefinition, RuleFinding, ScanContext
from . import library as _library
from . import injection as _injection
from . import wave17 as _wave17

class RuleEngine:
    def __init__(self) -> None:
        self._detectors: dict[str, Callable[[ScanContext, RuleDefinition], Sequence[RuleFinding]]] = {}
        self._register_builtin_detectors()

    def register(self, detector_name: str, detector: Callable[[ScanContext, RuleDefinition], Sequence[RuleFinding]]) -> None:
        self._detectors[detector_name] = detector

    def get_rule(self, rule_key: str) -> RuleDefinition:
        if rule_key not in RULE_INDEX:
            raise KeyError(f"Unknown rule: {rule_key}")
        return RULE_INDEX[rule_key]

    def list_rules(self, *, family: str | None = None, protocol: str | None = None, active_only: bool = True) -> list[RuleDefinition]:
        rules = []
        for rule in RULE_INDEX.values():
            if active_only and not rule.active:
                continue
            if family and rule.family.lower() != family.lower():
                continue
            if protocol and protocol.lower() not in {p.lower() for p in rule.protocols}:
                continue
            rules.append(rule)
        return sorted(rules, key=lambda r: (r.family, r.key))

    def evaluate(self, ctx: ScanContext, rule_keys: Iterable[str] | None = None) -> list[RuleFinding]:
        selected = [self.get_rule(k) for k in rule_keys] if rule_keys else self.list_rules(protocol=ctx.protocol)
        findings: list[RuleFinding] = []
        for rule in selected:
            detector = self._detectors.get(rule.detector)
            if not detector:
                continue
            findings.extend(detector(ctx, rule))
        return self._dedupe(findings)

    @staticmethod
    def _finding(rule: RuleDefinition, *, evidence: Sequence[Evidence], location: str = "") -> RuleFinding:
        return RuleFinding(
            rule_key=rule.key,
            title=rule.title,
            family=rule.family,
            severity=rule.severity,
            confidence=rule.confidence,
            description=rule.description,
            remediation=rule.remediation,
            evidence=tuple(evidence),
            owasp=rule.owasp,
            cwe=rule.cwe,
            tags=rule.tags,
            location=location,
        )

    def _register_builtin_detectors(self) -> None:
        self.register("header_absence", self._header_absence)
        self.register("csp_unsafe", self._csp_unsafe)
        self.register("csp_report_only", self._csp_report_only)
        self.register("csp_wildcard", self._csp_wildcard)
        self.register("cors_wildcard", self._cors_wildcard)
        self.register("cors_credentials", self._cors_credentials)
        self.register("cookie_secure", self._cookie_secure)
        self.register("cookie_httponly", self._cookie_httponly)
        self.register("cookie_samesite", self._cookie_samesite)
        self.register("reflection", self._reflection)
        self.register("dom_xss", self._dom_xss)
        self.register("db_error", self._db_error)
        self.register("command_error", self._command_error)
        self.register("path_error", self._path_error)
        self.register("clickjacking", self._clickjacking)
        self.register("mixed_content", self._mixed_content)
        self.register("server_disclosure", self._server_disclosure)
        self.register("error_signature", self._error_signature)
        self.register("url_parameter", self._url_parameter)
        self.register("context_review", self._context_review)
        self.register("openapi_security", self._context_review)
        self.register("authz_matrix", self._context_review)
        self.register("schema_additional_properties", self._context_review)
        self.register("resource_bounds", self._context_review)
        self.register("api_error_schema", self._context_review)
        self.register("inventory", self._context_review)
        self.register("graphql_limits", self._context_review)
        self.register("graphql_mutation_auth", self._context_review)
        self.register("soap_parser", self._context_review)
        self.register("grpc_reflection", self._context_review)
        self.register("llm_prompt_injection", self._context_review)
        self.register("llm_disclosure", self._context_review)
        self.register("llm_output", self._context_review)
        self.register("rag_injection", self._context_review)
        self.register("rag_tenant", self._context_review)
        self.register("agent_policy", self._context_review)
        self.register("agent_boundary", self._context_review)
        self.register("mcp_transport", self._context_review)
        self.register("sca_advisory", self._context_review)
        self.register("sca_kev", self._context_review)
        self.register("sca_epss", self._context_review)
        self.register("sca_license", self._context_review)
        self.register("sca_name_similarity", self._context_review)
        self.register("sca_sbom_diff", self._context_review)
        self.register("security_header_misconfig", _library.detect_security_header_misconfig)
        self.register("http_transport", _library.detect_http_transport)
        self.register("cache_control", _library.detect_cache_control)
        self.register("method_exposure", _library.detect_method_exposure)
        self.register("open_redirect", _library.detect_open_redirect)
        self.register("security_sensitive_response", _library.detect_security_sensitive_response)
        self.register("auth_session", _library.detect_auth_session)
        self.register("api_schema", _library.detect_api_schema)
        self.register("api_auth", _library.detect_api_auth)
        self.register("graphql", _library.detect_graphql)
        self.register("soap_grpc", _library.detect_soap_grpc)
        self.register("ai", _library.detect_ai)
        self.register("sca", _library.detect_sca)
        self.register("inj_evaluate", _injection.detect)
        self.register("wave17", _wave17.detect)

    @staticmethod
    def _header_absence(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        required = {"WEB-CSP-001": "content-security-policy", "WEB-HEAD-001": "strict-transport-security", "WEB-HEAD-002": "x-content-type-options", "WEB-HEAD-003": "referrer-policy"}
        header = required.get(rule.key)
        if header and header not in {k.lower() for k in ctx.headers} and not (header == "strict-transport-security" and not ctx.url.lower().startswith("https://")):
            return [RuleEngine._finding(rule, evidence=[Evidence("header", header, "missing")], location=ctx.url)]
        return []

    @staticmethod
    def _csp_unsafe(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        csp = ctx.headers.get("content-security-policy", "")
        if any(token in csp.lower() for token in ("'unsafe-inline'", "'unsafe-eval'")):
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "content-security-policy", csp[:500])], location=ctx.url)]
        return []

    @staticmethod
    def _csp_report_only(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        if ctx.headers.get("content-security-policy-report-only"):
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "content-security-policy-report-only", ctx.headers["content-security-policy-report-only"][:500])], location=ctx.url)]
        return []

    @staticmethod
    def _csp_wildcard(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        csp = ctx.headers.get("content-security-policy", "")
        if "*" in csp:
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "content-security-policy", csp[:500])], location=ctx.url)]
        return []

    @staticmethod
    def _cors_wildcard(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        if ctx.headers.get("access-control-allow-origin", "").strip() == "*":
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "access-control-allow-origin", "*")], location=ctx.url)]
        return []

    @staticmethod
    def _cors_credentials(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        if ctx.headers.get("access-control-allow-origin", "").strip() == "*" and ctx.headers.get("access-control-allow-credentials", "").lower() == "true":
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "cors", "origin=*; credentials=true")], location=ctx.url)]
        return []

    @staticmethod
    def _cookie_parts(ctx: ScanContext) -> list[str]:
        raw = ctx.headers.get("set-cookie", "")
        return [p.strip().lower() for p in raw.split(";") if p.strip()]

    def _cookie_secure(self, ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        parts = self._cookie_parts(ctx)
        if parts and "secure" not in parts:
            return [self._finding(rule, evidence=[Evidence("header", "set-cookie", ctx.headers.get("set-cookie", "")[:300])], location=ctx.url)]
        return []

    def _cookie_httponly(self, ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        parts = self._cookie_parts(ctx)
        if parts and "httponly" not in parts:
            return [self._finding(rule, evidence=[Evidence("header", "set-cookie", ctx.headers.get("set-cookie", "")[:300])], location=ctx.url)]
        return []

    def _cookie_samesite(self, ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        parts = self._cookie_parts(ctx)
        if parts and not any(p.startswith("samesite=") for p in parts):
            return [self._finding(rule, evidence=[Evidence("header", "set-cookie", ctx.headers.get("set-cookie", "")[:300])], location=ctx.url)]
        return []

    @staticmethod
    def _reflection(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        canaries = ["AegisXReflection", "aegisx-reflection-test"]
        if any(token in ctx.body for token in canaries):
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "controlled canary reflected")], location=ctx.url)]
        return []

    @staticmethod
    def _dom_xss(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        body = ctx.body.lower()
        if "location.search" in body and any(sink in body for sink in ("innerhtml", "document.write", "insertadjacenthtml")):
            return [RuleEngine._finding(rule, evidence=[Evidence("javascript", "body", "location.search -> DOM sink indicator")], location=ctx.url)]
        return []

    @staticmethod
    def _db_error(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        body = ctx.body.lower()
        markers = ("sql syntax", "ora-", "postgresql", "mysql", "sqlite error", "odbc sql")
        if any(marker in body for marker in markers):
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "database error marker")], location=ctx.url)]
        return []

    @staticmethod
    def _command_error(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        body = ctx.body.lower()
        markers = ("sh: ", "bash: ", "command not found", "powershell", "win32exception")
        if any(marker in body for marker in markers):
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "command execution marker")], location=ctx.url)]
        return []

    @staticmethod
    def _path_error(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        body = ctx.body.lower()
        markers = ("no such file or directory", "filenotfound", "directory traversal", "invalid path")
        if any(marker in body for marker in markers):
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "filesystem error marker")], location=ctx.url)]
        return []

    @staticmethod
    def _clickjacking(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        headers = {k.lower(): v for k, v in ctx.headers.items()}
        csp = headers.get("content-security-policy", "").lower()
        xfo = headers.get("x-frame-options", "").lower()
        if not xfo and "frame-ancestors" not in csp:
            return [RuleEngine._finding(rule, evidence=[Evidence("header", "frame-protection", "neither x-frame-options nor frame-ancestors")], location=ctx.url)]
        return []

    @staticmethod
    def _mixed_content(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        if ctx.url.lower().startswith("https://") and "http://" in ctx.body.lower():
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "http:// resource reference")], location=ctx.url)]
        return []

    @staticmethod
    def _server_disclosure(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        headers = {k.lower(): v for k, v in ctx.headers.items()}
        for key in ("server", "x-powered-by"):
            if key in headers and headers[key].strip():
                return [RuleEngine._finding(rule, evidence=[Evidence("header", key, headers[key][:200])], location=ctx.url)]
        return []

    @staticmethod
    def _error_signature(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        body = ctx.body.lower()
        markers = ("stack trace", "traceback (most recent call last)", "exception in thread", "at org.", "system.nullreferenceexception")
        if any(marker in body for marker in markers):
            return [RuleEngine._finding(rule, evidence=[Evidence("body", "response", "framework error/stack trace marker")], location=ctx.url)]
        return []

    @staticmethod
    def _url_parameter(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        keys = {str(p.get("name", "")).lower() for p in ctx.parameters}
        if keys & {"url", "uri", "redirect", "callback", "next", "image", "resource"}:
            return [RuleEngine._finding(rule, evidence=[Evidence("parameter", ",".join(sorted(keys & {"url","uri","redirect","callback","next","image","resource"})))], location=ctx.url)]
        return []

    @staticmethod
    def _context_review(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
        # Context-review rules are emitted only when explicit metadata signals the condition.
        flag_key = f"rule:{rule.key}"
        value = ctx.metadata.get(flag_key)
        if value:
            return [RuleEngine._finding(rule, evidence=[Evidence("metadata", flag_key, str(value))], location=ctx.url)]
        return []

    @staticmethod
    def _dedupe(findings: list[RuleFinding]) -> list[RuleFinding]:
        seen: set[tuple[str, str]] = set()
        output: list[RuleFinding] = []
        for item in findings:
            key = (item.rule_key, item.location)
            if key not in seen:
                seen.add(key)
                output.append(item)
        return output
