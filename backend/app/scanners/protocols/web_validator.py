from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import re
from urllib.parse import urlparse

@dataclass(frozen=True)
class ValidationIssue:
    key: str
    severity: str
    confidence: str
    title: str
    evidence: str
    remediation: str
    metadata: dict[str, Any] = field(default_factory=dict)

class WebDeepValidator:
    """Deterministic response validator; intentionally non-exploitative."""
    def analyze(self, *, url: str, status: int, headers: dict[str, str], body: str, parameters: list[dict[str, Any]] | None = None) -> list[ValidationIssue]:
        parameters = parameters or []
        h = {k.lower(): v for k, v in headers.items()}
        issues: list[ValidationIssue] = []
        body_l = body.lower()
        parsed = urlparse(url)
        if status in {500, 502, 503} and any(marker in body_l for marker in ("stack trace", "traceback", "exception", "fatal error")):
            issues.append(ValidationIssue("WEB-VAL-001", "medium", "high", "Verbose error response", "Server error status plus framework error marker", "Return generic external errors and keep detailed logs server-side."))
        if any(marker in body_l for marker in ("syntax error near", "sqlstate", "ora-", "mysql_fetch", "sqlite error")):
            issues.append(ValidationIssue("WEB-VAL-002", "high", "potential", "Database error indicator", "Database-specific error signature observed", "Use parameterized queries and avoid returning DB diagnostics."))
        if any(marker in body_l for marker in ("cannot find module", "child_process", "execve", "command not found")):
            issues.append(ValidationIssue("WEB-VAL-003", "critical", "potential", "Command execution error indicator", "Command/runtime error signature observed", "Avoid shell interpolation and use strict process allowlists."))
        if re.search(r"(?:/etc/passwd|\\windows\\system32|no such file or directory)", body_l):
            issues.append(ValidationIssue("WEB-VAL-004", "high", "potential", "Filesystem/path traversal indicator", "Filesystem path/error signature observed", "Canonicalize paths and enforce filesystem allowlists."))
        if parsed.scheme == "https" and re.search(r"(?:src|href)=[\"']http://", body, re.I):
            issues.append(ValidationIssue("WEB-VAL-005", "medium", "confirmed", "Mixed content reference", "HTTPS page contains an HTTP resource URL", "Serve all application resources over HTTPS."))
        location = h.get("location", "")
        if status in {301,302,303,307,308} and location.startswith(("http://", "https://")):
            issues.append(ValidationIssue("WEB-VAL-006", "medium", "potential", "External redirect target", f"Location={location[:200]}", "Validate redirect destinations against an allowlist."))
        if "set-cookie" in h:
            cookie = h["set-cookie"].lower()
            if "httponly" not in cookie:
                issues.append(ValidationIssue("WEB-VAL-007", "medium", "confirmed", "Cookie missing HttpOnly", "Set-Cookie lacks HttpOnly", "Set HttpOnly on authentication/session cookies where appropriate."))
            if "secure" not in cookie and parsed.scheme == "https":
                issues.append(ValidationIssue("WEB-VAL-008", "medium", "confirmed", "Cookie missing Secure", "HTTPS response sets cookie without Secure", "Set Secure on authentication/session cookies."))
        for p in parameters:
            if p.get("name") and p.get("location") in {"query", "path", "body"}:
                issues.append(ValidationIssue("WEB-VAL-009", "info", "confirmed", "Parameter validation opportunity", f"{p.get('location')} parameter: {p.get('name')}", "Apply context-appropriate validation and encoding."))
        return issues
