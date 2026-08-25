from __future__ import annotations
import base64, json, re
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import httpx


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def finding(key: str, title: str, severity: str, category: str, description: str, evidence=None, remediation: str = ""):
    return {
        "finding_key": key,
        "title": title,
        "severity": severity,
        "confidence": "confirmed",
        "category": category,
        "description": description,
        "evidence": evidence or {},
        "remediation": remediation,
    }


def parse_csp(value: str) -> dict:
    directives = {}
    for raw in value.split(";"):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        name = parts[0].lower()
        directives[name] = parts[1:]
    return directives


def analyze_csp(header: str | None, report_only: str | None = None) -> dict:
    findings = []
    policy = header or report_only
    if not policy:
        findings.append(finding("CSP-001", "Content Security Policy header missing", "medium", "CSP", "The response did not expose a Content-Security-Policy header.", remediation="Deploy an enforced CSP appropriate to the application."))
        return {"present": False, "report_only": False, "directives": {}, "findings": findings}

    directives = parse_csp(policy)
    report = header is None and report_only is not None
    if report:
        findings.append(finding("CSP-002", "CSP is report-only", "medium", "CSP", "A CSP-Report-Only policy is present but not enforced.", remediation="Move a tested policy to Content-Security-Policy enforcement."))

    if "default-src" not in directives:
        findings.append(finding("CSP-003", "default-src directive missing", "low", "CSP", "The policy does not define a default source policy; other fetch directives must be reviewed individually.", remediation="Define a least-privilege default-src where appropriate."))
    for directive, key, title, sev in [
        ("script-src", "CSP-004", "unsafe-inline enabled for scripts", "high"),
        ("style-src", "CSP-005", "unsafe-inline enabled for styles", "medium"),
        ("script-src", "CSP-006", "unsafe-eval enabled for scripts", "high"),
    ]:
        vals = directives.get(directive, [])
        token = "'unsafe-inline'" if "inline" in title else "'unsafe-eval'"
        if token in vals:
            findings.append(finding(key, title, sev, "CSP", f"{directive} contains {token}.", evidence={"directive": directive, "value": vals}, remediation="Prefer nonces or hashes and remove unsafe execution sources."))

    for directive, key, title in [
        ("script-src", "CSP-007", "Wildcard script source",),
        ("connect-src", "CSP-008", "Wildcard connect source",),
        ("img-src", "CSP-009", "Wildcard image source",),
        ("font-src", "CSP-010", "Wildcard font source",),
    ]:
        vals = directives.get(directive, [])
        if "*" in vals:
            findings.append(finding(key, title, "medium", "CSP", f"{directive} allows any origin.", evidence={"directive": directive, "value": vals}, remediation="Replace wildcards with explicit trusted origins."))

    if "object-src" not in directives or "'none'" not in directives.get("object-src", []):
        findings.append(finding("CSP-011", "object-src is not restricted to 'none'", "low", "CSP", "Legacy plugin content is not explicitly blocked.", remediation="Use object-src 'none' unless the application has a documented requirement."))
    if "base-uri" not in directives:
        findings.append(finding("CSP-012", "base-uri directive missing", "low", "CSP", "The policy does not explicitly constrain document base URL manipulation.", remediation="Consider base-uri 'self' or a stricter policy."))
    if "frame-ancestors" not in directives:
        findings.append(finding("CSP-013", "frame-ancestors directive missing", "low", "CSP", "CSP does not declare embedding policy.", remediation="Set frame-ancestors according to application embedding requirements."))

    score = max(0, 100 - sum(25 if f["severity"] == "high" else 12 if f["severity"] == "medium" else 6 for f in findings))
    return {"present": True, "report_only": report, "directives": directives, "findings": findings, "score": score}


def _b64json(segment: str):
    pad = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode((segment + pad).encode())
    return json.loads(raw.decode("utf-8"))


def audit_jwt(token: str) -> dict:
    findings = []
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"valid_structure": False, "error": "JWT must have three dot-separated segments.", "findings": [finding("JWT-001", "Invalid JWT structure", "medium", "JWT", "The supplied token is not a three-part compact JWT.")]}
    try:
        header = _b64json(parts[0]); payload = _b64json(parts[1])
    except Exception as exc:
        return {"valid_structure": False, "error": f"Invalid Base64URL/JSON: {exc}", "findings": [finding("JWT-002", "JWT encoding is invalid", "medium", "JWT", "The header or payload could not be decoded as Base64URL JSON.")]}

    alg = str(header.get("alg", "")).upper()
    if alg == "NONE":
        findings.append(finding("JWT-003", "Unsecured JWT algorithm declared", "critical", "JWT", "The token declares alg=none.", evidence={"alg": alg}, remediation="Allow only explicitly approved signing algorithms and require signature verification."))
    if not alg:
        findings.append(finding("JWT-004", "JWT algorithm missing", "high", "JWT", "The JWT header does not declare an algorithm."))
    if "exp" not in payload:
        findings.append(finding("JWT-005", "JWT expiration claim missing", "medium", "JWT", "The payload has no exp claim.", remediation="Enforce bounded token lifetimes."))
    else:
        try:
            exp = int(payload["exp"]); now = int(datetime.now(timezone.utc).timestamp())
            if exp < now:
                findings.append(finding("JWT-006", "JWT is expired", "low", "JWT", "The token expiration is in the past.", evidence={"exp": exp, "now": now}))
            elif exp - now > 86400 * 7:
                findings.append(finding("JWT-007", "JWT lifetime exceeds seven days", "medium", "JWT", "The token has an unusually long lifetime.", evidence={"lifetime_seconds": exp - now}, remediation="Use short-lived access tokens and refresh-token rotation."))
        except (TypeError, ValueError):
            findings.append(finding("JWT-008", "JWT exp claim is not numeric", "medium", "JWT", "The exp claim could not be interpreted as a NumericDate."))
    for claim, key, title in [("iss", "JWT-009", "Issuer claim missing"), ("aud", "JWT-010", "Audience claim missing")]:
        if claim not in payload:
            findings.append(finding(key, title, "low", "JWT", f"The {claim} claim is not present; application-side validation should be reviewed."))

    sensitive = []
    for k, v in payload.items():
        if re.search(r"pass(word)?|secret|api[_-]?key|private[_-]?key|access[_-]?token", k, re.I):
            sensitive.append(k)
    if sensitive:
        findings.append(finding("JWT-011", "Sensitive-looking claims present", "high", "JWT", "The token contains claim names that appear to carry secrets or authentication material.", evidence={"claims": sensitive}, remediation="Keep secrets and long-lived credentials out of JWT payloads."))

    return {
        "valid_structure": True,
        "header": header,
        "payload": payload,
        "signature_present": bool(parts[2]),
        "signature_segment_length": len(parts[2]),
        "algorithm": alg,
        "findings": findings,
        "secret_key": "not derivable from JWT; provide a verification secret/key for signature testing",
    }


def analyze_cors(headers: dict) -> dict:
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    findings = []
    if acao == "*" and str(acac).lower() == "true":
        findings.append(finding("CORS-001", "Wildcard origin with credentials", "high", "CORS", "Access-Control-Allow-Origin is wildcard while credentials are enabled.", remediation="Use an explicit allowlist of trusted origins."))
    elif acao == "*":
        findings.append(finding("CORS-002", "Wildcard CORS origin", "medium", "CORS", "Any origin may read eligible cross-origin responses.", remediation="Restrict origins where sensitive responses are exposed."))
    return {"allow_origin": acao, "allow_credentials": acac, "findings": findings}


def analyze_headers(headers: dict) -> dict:
    checks = {
        "strict-transport-security": ("HSTS missing", "medium"),
        "x-content-type-options": ("X-Content-Type-Options missing", "low"),
        "referrer-policy": ("Referrer-Policy missing", "low"),
        "content-security-policy": ("CSP missing", "medium"),
        "permissions-policy": ("Permissions-Policy missing", "low"),
    }
    findings=[]
    lower={k.lower():v for k,v in headers.items()}
    for h,(title,sev) in checks.items():
        if h not in lower:
            findings.append(finding("HDR-" + h.upper().replace("-", "_"), title, sev, "Security Headers", f"The response did not include {h}."))
    return {"headers": lower, "findings": findings}


def analyze_cookies(headers: dict) -> dict:
    raw = headers.get("set-cookie", "")
    cookie_lines = raw.split("\n") if raw else []
    findings=[]
    parsed=[]
    for line in cookie_lines:
        first=line.split(";",1)[0]
        name=first.split("=",1)[0].strip()
        attrs={x.strip().lower() for x in line.split(";")[1:]}
        parsed.append({"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs, "samesite": next((a.split("=",1)[1] for a in attrs if a.startswith("samesite=")), None)})
    for c in parsed:
        if not c["secure"]:
            findings.append(finding("COOKIE-001", f"Cookie {c['name']} missing Secure flag", "medium", "Cookies", "Cookie may be sent over cleartext HTTP.", remediation="Set Secure on security-sensitive cookies."))
        if not c["httponly"]:
            findings.append(finding("COOKIE-002", f"Cookie {c['name']} missing HttpOnly flag", "medium", "Cookies", "Client-side scripts may access the cookie.", remediation="Set HttpOnly for session/authentication cookies."))
        if not c["samesite"]:
            findings.append(finding("COOKIE-003", f"Cookie {c['name']} missing SameSite attribute", "low", "Cookies", "Cross-site cookie sending behavior is not explicitly constrained."))
    return {"cookies": parsed, "findings": findings}


def analyze_oauth_oidc(url: str) -> dict:
    p = urlparse(url)
    findings=[]
    if p.scheme != "https":
        findings.append(finding("OAUTH-001", "OAuth/OIDC endpoint uses HTTP", "high", "OAuth/OIDC", "The supplied OAuth/OIDC URL is not HTTPS.", remediation="Use TLS for authorization and token endpoints."))
    return {"url": url, "host": p.netloc, "path": p.path, "query_keys": sorted(parse_qs(p.query).keys()), "findings": findings}


async def fetch_url(url: str) -> dict:
    async with httpx.AsyncClient(follow_redirects=True, timeout=12, headers={"User-Agent":"AegisX-Security-Analyzer/1.0"}) as client:
        r = await client.get(url)
        return {"url": str(r.url), "status_code": r.status_code, "headers": dict(r.headers), "text_prefix": r.text[:5000]}
