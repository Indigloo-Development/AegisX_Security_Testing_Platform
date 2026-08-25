from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import secrets
from typing import Any

from .models import Evidence, RuleDefinition, RuleFinding, ScanContext


@dataclass(frozen=True)
class InjectionSignal:
    key: str
    family: str
    severity: str
    description: str
    remediation: str


def create_oast_token(scan_id: str, length: int = 24) -> str:
    """Create a non-routable correlation identifier for an external OAST provider.

    The engine never performs a callback itself; a customer-controlled OAST service can
    use this token as a correlation value in an authorized scan.
    """
    digest = hashlib.sha256(f"{scan_id}:{secrets.token_hex(16)}".encode()).hexdigest()
    return digest[:max(12, min(length, 64))]


def _finding(rule: RuleDefinition, ctx: ScanContext, reason: str, location: str) -> RuleFinding:
    return RuleFinding(
        rule_key=rule.key,
        title=rule.title,
        family=rule.family,
        severity=rule.severity,
        confidence=rule.confidence,
        description=rule.description,
        remediation=rule.remediation,
        evidence=(Evidence("injection", location, reason),),
        owasp=rule.owasp,
        cwe=rule.cwe,
        tags=rule.tags,
        location=ctx.url,
    )


def detect(ctx: ScanContext, rule: RuleDefinition) -> list[RuleFinding]:
    body = (ctx.body or "").lower()
    headers = {k.lower(): v for k, v in ctx.headers.items()}
    m: dict[str, Any] = ctx.metadata

    if rule.key == "INJ-SQL-001":
        db_markers = ("sql syntax", "sqlstate", "ora-", "postgresql error", "mysql error", "sqlite error", "odbc sql")
        if m.get("controlled_input_variation") is True and any(x in body for x in db_markers):
            return [_finding(rule, ctx, "controlled input variation correlated with a database error signature", "response.body")]

    if rule.key == "INJ-SQL-002":
        if m.get("differential_db_behavior") is True:
            return [_finding(rule, ctx, "authorized differential analysis reported database-dependent behavior", "response.diff")]

    if rule.key == "INJ-SSRF-001":
        candidates = {str(p.get("name", "")).lower() for p in ctx.parameters}
        candidates &= {"url", "uri", "callback", "webhook", "image", "resource", "next", "redirect"}
        if candidates and m.get("server_side_fetch_candidate") is True:
            return [_finding(rule, ctx, f"server-side fetch candidate parameter(s): {', '.join(sorted(candidates))}", "request.parameters")]

    if rule.key == "INJ-SSRF-002":
        token = m.get("oast_token")
        observed = m.get("oast_callback_observed") is True
        if token and observed:
            return [_finding(rule, ctx, f"authorized callback correlation token observed: {str(token)[:64]}", "oast.callback")]

    if rule.key == "INJ-SSTI-001":
        markers = ("jinja2", "freemarker", "thymeleaf", "template syntax error", "templateinterpolation")
        if m.get("controlled_template_probe") is True and any(x in body for x in markers):
            return [_finding(rule, ctx, "controlled template probe correlated with template-engine error behavior", "response.body")]

    if rule.key == "INJ-XXE-001":
        xml_type = (headers.get("content-type", "") + " " + ctx.content_type).lower()
        if "xml" in xml_type and m.get("external_entity_processing") is True:
            return [_finding(rule, ctx, "authorized parser metadata indicates external entity processing", "parser.metadata")]

    if rule.key == "INJ-LDAP-001":
        if m.get("ldap_error_observed") is True or "ldap error" in body:
            return [_finding(rule, ctx, "LDAP parser/error indicator observed during authorized validation", "response.body")]

    if rule.key == "INJ-XPATH-001":
        if m.get("xpath_error_observed") is True or "xpath" in body and "error" in body:
            return [_finding(rule, ctx, "XPath parser/error indicator observed during authorized validation", "response.body")]

    if rule.key == "INJ-CRLF-001":
        if m.get("header_injection_indicator") is True:
            return [_finding(rule, ctx, "response behavior indicates user-controlled header boundary manipulation", "response.headers")]

    return []
