from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import httpx

CANARY = "AEGISX-CANARY-7F3A"

def _finding(key, title, severity, confidence, desc, rem, evidence):
    return {"finding_key": key, "title": title, "severity": severity, "confidence": confidence, "category": "Web DAST", "description": desc, "remediation": rem, "evidence": evidence}

def safe_active_probe(url: str, *, timeout: float = 15.0) -> list[dict]:
    """Non-destructive GET-only probes. Never submits forms or uses state-changing HTTP methods."""
    findings: list[dict] = []
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Target must be an absolute HTTP/HTTPS URL")
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not query:
        return findings
    for name in list(query)[:5]:
        mutated = dict(query)
        mutated[name] = CANARY
        new_query = urlencode(mutated, doseq=True)
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "AegisX-Commercial-DAST/1.0"}) as client:
            response = client.get(test_url)
        body = response.text[:1_000_000]
        if CANARY in body:
            findings.append(_finding(
                "WEB-REFLECTION-001",
                "User-controlled query value reflected in response",
                "medium",
                "likely",
                "A canary value supplied through a query parameter was reflected into the response body. Reflection alone does not prove XSS; context-sensitive validation is required.",
                "Apply contextual output encoding and validate dangerous reflection contexts. Perform browser-based XSS validation only in an explicitly authorized deep profile.",
                {"url": str(response.url), "parameter": name, "canary": CANARY, "status_code": response.status_code}
            ))
        if re.search(r"<title[^>]*>[^<]*AEGISX-CANARY", body, re.I):
            findings.append(_finding(
                "WEB-REFLECTION-TITLE-001",
                "Canary reflected into HTML title context",
                "high",
                "likely",
                "The canary value was reflected within a title element. This is a higher-risk HTML reflection context but still requires safe browser validation before confirmation.",
                "Use contextual HTML encoding and avoid inserting untrusted data into document markup.",
                {"url": str(response.url), "parameter": name, "context": "title"}
            ))
    return findings
