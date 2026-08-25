from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs
from typing import Any, Iterable
from .models import ValidationFinding, WorkflowAnalysis, WorkflowStep


def _f(key: str, title: str, severity: str, confidence: str, category: str, *, cwe=(), owasp=(), description="", remediation="", **evidence) -> dict[str, Any]:
    return ValidationFinding(key, title, severity, confidence, category, tuple(cwe), tuple(owasp), description, remediation, evidence).as_dict()

_SQL_ERRORS = [
    r"sql syntax.*mysql", r"you have an error in your sql syntax", r"postgresql.*error",
    r"pg::(?:syntax|undefined).*error", r"sqlite error", r"ora-\d{4,}", r"microsoft sql server",
    r"unclosed quotation mark after the character string", r"odbc sql server driver",
]
_CMD_ERRORS = [r"/bin/(?:sh|bash):", r"command not found", r"cannot execute binary file", r"powershell.*not recognized"]


def analyze_reflection_and_dom(body: str, url: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not body:
        return out
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for name, values in params.items():
        for value in values[:3]:
            if value and value in body:
                # Reflection is not treated as XSS confirmation.
                out.append(_f("WEB-XSS-REFLECTION-001", "Potential reflected input", "medium", "potential", "Injection", cwe=("CWE-79",), owasp=("A05:2025",), description="A URL parameter value was reflected in the response; contextual output encoding and sink analysis are required before confirming XSS.", remediation="Apply context-appropriate output encoding and validate untrusted input at relevant HTML/JS sinks.", parameter=name, reflected_value=value[:120], url=url))
                break
    # Lightweight DOM sink/source pairing. No exploit payloads are generated.
    sink_patterns = [r"innerHTML\s*=", r"outerHTML\s*=", r"document\.write\s*\(", r"insertAdjacentHTML\s*\(", r"eval\s*\("]
    source_patterns = [r"location\.(?:hash|search)", r"document\.URL", r"document\.referrer", r"window\.name"]
    sinks = [p for p in sink_patterns if re.search(p, body, re.I)]
    sources = [p for p in source_patterns if re.search(p, body, re.I)]
    if sinks and sources:
        out.append(_f("WEB-XSS-DOM-001", "Potential DOM XSS source-to-sink path", "high", "potential", "Injection", cwe=("CWE-79",), owasp=("A05:2025",), description="A script contains a browser-controlled source and a potentially dangerous DOM/code sink. Static matching does not prove exploitability.", remediation="Prefer safe DOM APIs and context-aware encoding; avoid dangerous string-to-code or HTML sinks for untrusted data.", sources=sources, sinks=sinks[:5], url=url))
    return out


def analyze_injection_errors(body: str, url: str) -> list[dict[str, Any]]:
    text = body or ""
    out: list[dict[str, Any]] = []
    for pattern in _SQL_ERRORS:
        match = re.search(pattern, text, re.I)
        if match:
            out.append(_f("WEB-SQLI-ERROR-001", "Database error disclosure indicator", "medium", "potential", "Injection", cwe=("CWE-89", "CWE-209"), owasp=("A05:2025",), description="The response contains a database-error signature. This can indicate unsafe error handling or an injection pathway, but does not by itself confirm SQL injection.", remediation="Use parameterized queries, safe ORM/query APIs and generic external error responses.", pattern=pattern, match=match.group(0)[:180], url=url))
            break
    for pattern in _CMD_ERRORS:
        match = re.search(pattern, text, re.I)
        if match:
            out.append(_f("WEB-CMD-ERROR-001", "Command execution error indicator", "medium", "potential", "Injection", cwe=("CWE-78",), owasp=("A05:2025",), description="The response contains a command execution error signature. Static evidence is insufficient to prove command injection.", remediation="Avoid shell invocation where possible; use argument-safe process APIs and strict allowlists.", pattern=pattern, match=match.group(0)[:180], url=url))
            break
    if re.search(r"(?:file not found|no such file or directory|directory traversal|path traversal)", text, re.I):
        out.append(_f("WEB-PATH-ERROR-001", "Filesystem/path error indicator", "low", "potential", "Injection", cwe=("CWE-22",), owasp=("A05:2025",), description="A filesystem-oriented error message was observed; validate path handling and canonicalization.", remediation="Canonicalize paths and enforce allowlisted base directories before filesystem access.", url=url))
    return out


def analyze_csrf_and_sessions(*, html: str, response_headers: dict[str, str], request_url: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    forms = re.findall(r"<form\b([^>]*)>(.*?)</form>", html or "", re.I | re.S)
    for attrs, body in forms:
        method_m = re.search(r"\bmethod\s*=\s*[\"']([^\"']+)", attrs, re.I)
        method = (method_m.group(1) if method_m else "get").upper()
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            has_token = bool(re.search(r"csrf|xsrf|anti.?forgery|authenticity_token", body, re.I))
            if not has_token:
                out.append(_f("WEB-CSRF-001", "State-changing form lacks an obvious CSRF token", "medium", "potential", "Request Integrity", cwe=("CWE-352",), owasp=("A01:2025", "A07:2025"), description="A state-changing HTML form has no obvious synchronizer token marker. SameSite or origin checks may provide equivalent protection.", remediation="Use a server-validated CSRF token or an equivalent strong origin/request integrity control.", method=method, url=request_url))
    return out


def analyze_session_rotation(before_cookies: Iterable[str], after_cookies: Iterable[str]) -> list[dict[str, Any]]:
    before = {x.split("=", 1)[0].strip() for x in before_cookies if "=" in x}
    after = {x.split("=", 1)[0].strip() for x in after_cookies if "=" in x}
    shared = before & after
    if shared:
        return [_f("WEB-SESSION-001", "Session identifier did not rotate during supplied workflow", "high", "potential", "Session Management", cwe=("CWE-384",), owasp=("A07:2025",), description="The supplied before/after cookie metadata retained the same session-like cookie name. Value rotation must be validated at runtime to confirm fixation risk.", remediation="Rotate the authenticated session identifier after privilege changes or login and invalidate the pre-authentication session.", cookies=sorted(shared))]
    return []


def analyze_workflow(steps: list[WorkflowStep]) -> WorkflowAnalysis:
    result = WorkflowAnalysis()
    previous = None
    seen: set[str] = set()
    for idx, step in enumerate(steps):
        normalized = {"index": idx, "name": step.name, "method": step.method.upper(), "path": step.path, "requires_auth": step.requires_auth, "state_change": step.state_change, "expected_role": step.expected_role}
        result.normalized_steps.append(normalized)
        key = f"{step.method.upper()} {step.path}"
        if key in seen:
            result.warnings.append(f"Repeated workflow step: {key}")
        seen.add(key)
        if step.state_change and step.method.upper() in {"GET", "HEAD", "OPTIONS"}:
            result.findings.append(_f("WEB-BL-001", "State-changing workflow step uses a safe/read-oriented HTTP method", "medium", "potential", "Business Logic", cwe=("CWE-840",), owasp=("A06:2025",), description="A workflow model marks a GET-like operation as changing application state, which can create CSRF/cache/link-triggered risks.", remediation="Use POST/PUT/PATCH/DELETE semantics for state-changing operations and enforce request integrity controls.", step=normalized))
        if previous and step.requires_auth and not previous.get("requires_auth") and step.name.lower().startswith(("confirm", "change", "delete", "transfer", "approve")):
            result.warnings.append(f"Sensitive transition should be re-authorized: {previous['name']} -> {step.name}")
        previous = normalized
    if any(s.state_change for s in steps) and not any(s.requires_auth for s in steps if s.state_change):
        result.findings.append(_f("WEB-BL-002", "State-changing business workflow lacks explicit authorization markers", "high", "potential", "Business Logic", cwe=("CWE-862", "CWE-863"), owasp=("A01:2025", "A06:2025"), description="The workflow definition contains state changes but no explicit authorization requirement. This is a planning signal, not proof of an authorization bypass.", remediation="Require server-side authorization at every privileged state transition and verify the actor/resource relationship.", steps=[s.name for s in steps]))
    return result
