from __future__ import annotations

from typing import Any


def finding(key: str, title: str, severity: str, confidence: str, category: str, description: str, remediation: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_key": key,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "description": description,
        "remediation": remediation,
        "evidence": evidence,
    }


def analyze_headers(url: str, headers: dict[str, str], status_code: int) -> list[dict[str, Any]]:
    lower = {k.lower(): v for k, v in headers.items()}
    findings: list[dict[str, Any]] = []

    if "content-security-policy" not in lower and "content-security-policy-report-only" not in lower:
        findings.append(finding(
            "WEB-CSP-001", "Content Security Policy header missing", "medium", "confirmed", "Security Headers",
            "The response does not expose a Content-Security-Policy or Content-Security-Policy-Report-Only header.",
            "Define a restrictive CSP appropriate to the application and enforce it after testing.",
            {"url": url, "status_code": status_code},
        ))

    security_headers = {
        "strict-transport-security": ("WEB-HDR-001", "Strict-Transport-Security header missing", "medium", "Enable HSTS on HTTPS applications after confirming subdomain and certificate coverage."),
        "x-content-type-options": ("WEB-HDR-002", "X-Content-Type-Options header missing", "low", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("WEB-HDR-003", "Referrer-Policy header missing", "low", "Set an explicit Referrer-Policy such as strict-origin-when-cross-origin."),
    }
    for header, (key, title, severity, remediation) in security_headers.items():
        if header not in lower:
            findings.append(finding(key, title, severity, "confirmed", "Security Headers", f"The response is missing {header}.", remediation, {"url": url}))

    xfo = lower.get("x-frame-options", "")
    csp = lower.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        findings.append(finding(
            "WEB-CLICKJACK-001", "Clickjacking protection not observed", "medium", "confirmed", "Security Headers",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed on the tested response.",
            "Use CSP frame-ancestors and/or X-Frame-Options according to your browser support requirements.", {"url": url}
        ))

    server = lower.get("server")
    powered = lower.get("x-powered-by")
    if server and len(server) > 0:
        findings.append(finding(
            "WEB-INFO-001", "Server technology disclosed in response headers", "info", "confirmed", "Information Disclosure",
            "The Server header exposes implementation details that may assist technology fingerprinting.",
            "Minimize unnecessary server banner disclosure where operationally practical.", {"server": server, "url": url}
        ))
    if powered:
        findings.append(finding(
            "WEB-INFO-002", "X-Powered-By technology disclosure", "low", "confirmed", "Information Disclosure",
            "The X-Powered-By header exposes application framework information.",
            "Remove or minimize X-Powered-By response headers in production.", {"x-powered-by": powered, "url": url}
        ))
    return findings
