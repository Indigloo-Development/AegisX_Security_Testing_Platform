from __future__ import annotations
import re
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse, urljoin
from .models import PageContext
from .rules import get_rule

SENSITIVE_COOKIE_NAMES = re.compile(r"(sess|session|auth|token|jwt|sid|csrf|identity)", re.I)
STACK_PATTERNS = [re.compile(p, re.I) for p in [r"traceback \(most recent call last\)", r"exception in thread", r"stack trace", r"at [\w.$]+\([\w.$]+:\d+\)", r"django.*debug", r"werkzeug debugger"]]
DEBUG_PATTERNS = [re.compile(p, re.I) for p in [r"debug toolbar", r"debug=true", r"development mode", r"__next_data__", r"webpack-dev-server"]]
DIRECTORY_PATTERNS = [re.compile(p, re.I) for p in [r"<title>index of /", r"<h1>index of /", r"directory listing for /"]]

def _f(rule_key: str, url: str, evidence: dict[str, Any], *, confidence: str | None = None) -> dict[str, Any]:
    r = get_rule(rule_key)
    return {
        "finding_key": r.key, "title": r.title, "severity": r.severity,
        "confidence": confidence or r.confidence, "category": r.category,
        "description": r.description, "remediation": r.remediation,
        "evidence": {"url": url, **evidence}, "owasp": list(r.owasp), "cwe": list(r.cwe), "tags": list(r.tags),
    }

def analyze_csp(ctx: PageContext) -> list[dict[str, Any]]:
    csp = ctx.headers.get("content-security-policy", "")
    if not csp:
        return [_f("WEB-CSP-001", ctx.url, {"header": "Content-Security-Policy"})]
    findings = []
    low = csp.lower()
    if "'unsafe-inline'" in low:
        findings.append(_f("WEB-CSP-002", ctx.url, {"directive": "unsafe-inline"}))
    if "'unsafe-eval'" in low:
        findings.append(_f("WEB-CSP-003", ctx.url, {"directive": "unsafe-eval"}))
    for directive in ("script-src", "object-src", "default-src", "connect-src", "frame-src"):
        m = re.search(rf"(?:^|;)\s*{re.escape(directive)}\s+([^;]+)", csp, re.I)
        if m and "*" in m.group(1) and directive in {"script-src", "object-src", "connect-src"}:
            findings.append(_f("WEB-CSP-004", ctx.url, {"directive": directive, "value": m.group(1).strip()}))
    return findings

def analyze_headers(ctx: PageContext) -> list[dict[str, Any]]:
    h = {k.lower(): v for k, v in ctx.headers.items()}
    findings = analyze_csp(ctx)
    if ctx.url.lower().startswith("https://") and "strict-transport-security" not in h:
        findings.append(_f("WEB-HDR-001", ctx.url, {"missing": "strict-transport-security"}))
    for key in ("x-content-type-options", "referrer-policy", "permissions-policy"):
        rule = {"x-content-type-options": "WEB-HDR-002", "referrer-policy": "WEB-HDR-003", "permissions-policy": "WEB-HDR-004"}[key]
        if key not in h:
            findings.append(_f(rule, ctx.url, {"missing": key}))
    if not h.get("cross-origin-opener-policy") or not h.get("cross-origin-resource-policy"):
        findings.append(_f("WEB-HDR-005", ctx.url, {"coop": h.get("cross-origin-opener-policy"), "corp": h.get("cross-origin-resource-policy")}, confidence="potential"))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower():
        findings.append(_f("WEB-CLICKJACK-001", ctx.url, {}))
    if h.get("access-control-allow-origin") == "*":
        findings.append(_f("WEB-CORS-001", ctx.url, {"allow-origin": "*"}))
        if h.get("access-control-allow-credentials", "").lower() == "true":
            findings.append(_f("WEB-CORS-002", ctx.url, {"allow-origin": "*", "allow-credentials": "true"}))
    if h.get("server"):
        findings.append(_f("WEB-INFO-001", ctx.url, {"server": h["server"]}))
    if h.get("x-powered-by"):
        findings.append(_f("WEB-INFO-002", ctx.url, {"x-powered-by": h["x-powered-by"]}))
    ctype = h.get("content-type", "")
    if "nosniff" not in h.get("x-content-type-options", "").lower() and ctype:
        pass
    cache = h.get("cache-control", "")
    if SENSITIVE_COOKIE_NAMES.search(ctx.body[:5000] or "") and not any(x in cache.lower() for x in ("no-store", "private")):
        findings.append(_f("WEB-CACHE-001", ctx.url, {"cache-control": cache or None}, confidence="potential"))
    return findings

def analyze_cookies(ctx: PageContext) -> list[dict[str, Any]]:
    raw = ctx.headers.get("set-cookie", "")
    if not raw:
        return []
    cookie = SimpleCookie()
    try:
        cookie.load(raw)
    except Exception:
        return []
    out = []
    for name, morsel in cookie.items():
        attrs = {k.lower(): morsel[k] for k in morsel.keys() if morsel[k]}
        sensitive = bool(SENSITIVE_COOKIE_NAMES.search(name))
        if sensitive and ctx.url.lower().startswith("https://") and "secure" not in attrs:
            out.append(_f("WEB-COOKIE-001", ctx.url, {"cookie": name, "missing": "Secure"}))
        if sensitive and "httponly" not in attrs:
            out.append(_f("WEB-COOKIE-002", ctx.url, {"cookie": name, "missing": "HttpOnly"}))
        if sensitive and attrs.get("samesite", "").lower() in {"", "none"}:
            out.append(_f("WEB-COOKIE-003", ctx.url, {"cookie": name, "samesite": attrs.get("samesite") or None}))
        if "path" not in attrs:
            out.append(_f("WEB-COOKIE-004", ctx.url, {"cookie": name}))
    return out

def analyze_body(ctx: PageContext) -> list[dict[str, Any]]:
    body = ctx.body or ""
    out = []
    if any(p.search(body) for p in STACK_PATTERNS):
        out.append(_f("WEB-ERROR-001", ctx.url, {"indicator": "stack-trace-like pattern"}, confidence="potential"))
    if any(p.search(body) for p in DEBUG_PATTERNS):
        out.append(_f("WEB-ERROR-002", ctx.url, {"indicator": "debug tooling pattern"}, confidence="potential"))
    if any(p.search(body[:20000]) for p in DIRECTORY_PATTERNS):
        out.append(_f("WEB-APP-002", ctx.url, {"indicator": "directory listing marker"}, confidence="potential"))
    if ctx.url.startswith("https://"):
        for ref in re.findall(r'''(?:src|href|action)\s*=\s*["']([^"']+)['"]''', body, re.I):
            absolute = urljoin(ctx.url, ref)
            if absolute.lower().startswith("http://"):
                out.append(_f("WEB-TRANSPORT-001", ctx.url, {"reference": absolute}, confidence="confirmed"))
                break
    if ".map" in body and re.search(r"sourceMappingURL\s*=\s*[^\s]+", body, re.I):
        out.append(_f("WEB-APP-001", ctx.url, {"indicator": "sourceMappingURL"}, confidence="confirmed"))
    return out

def analyze_forms_and_inventory(ctx: PageContext) -> list[dict[str, Any]]:
    out = []
    form_pattern = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
    for attrs, form_body in form_pattern.findall(ctx.body or ""):
        action_m = re.search(r"\baction\s*=\s*[\"']([^\"']*)", attrs, re.I)
        action = action_m.group(1) if action_m else ""
        if not action:
            out.append(_f("WEB-APP-005", ctx.url, {"form_action": "implicit-current-document"}, confidence="potential"))
        input_names = re.findall(r"\bname\s*=\s*[\"']([^\"']+)[\"']", form_body, re.I)
        if any(re.search(r"password|passwd|secret", x, re.I) for x in input_names) and action.lower().startswith("http://"):
            out.append(_f("WEB-TRANSPORT-002", ctx.url, {"action": action, "inputs": input_names}))
    return out

def analyze_page(ctx: PageContext) -> list[dict[str, Any]]:
    return analyze_headers(ctx) + analyze_cookies(ctx) + analyze_body(ctx) + analyze_forms_and_inventory(ctx)
