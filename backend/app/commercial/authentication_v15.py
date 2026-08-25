from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class AuthWorkflow:
    name: str
    steps: List[Dict[str, Any]] = field(default_factory=list)
    requires_mfa: bool = False
    success_marker: Optional[str] = None


@dataclass
class SessionObservation:
    session_before: Optional[str]
    session_after_login: Optional[str]
    session_after_privilege_change: Optional[str] = None
    session_after_logout: Optional[str] = None
    token_before: Optional[str] = None
    token_after: Optional[str] = None


@dataclass
class AuthFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    evidence: Dict[str, Any]
    remediation: str


def analyze_login_workflow(workflow: AuthWorkflow) -> List[AuthFinding]:
    findings: List[AuthFinding] = []
    steps = [str(s.get("name", "")).lower() for s in workflow.steps]
    names = set(steps)
    if workflow.requires_mfa and not any("mfa" in s or "otp" in s or "factor" in s for s in steps):
        findings.append(AuthFinding(
            "AUTH-MFA-001", "MFA declared but no MFA verification step observed", "HIGH", "POTENTIAL", "authentication",
            {"workflow": workflow.name, "steps": workflow.steps},
            "Ensure MFA is enforced server-side before the authenticated session is issued.",
        ))
    if any("login" in s for s in steps) and not workflow.success_marker:
        findings.append(AuthFinding(
            "AUTH-FLOW-001", "Authentication workflow lacks an explicit success indicator", "MEDIUM", "POTENTIAL", "authentication",
            {"workflow": workflow.name},
            "Use a deterministic authenticated-state indicator to avoid ambiguous login verification.",
        ))
    if "password reset" in names or any("reset" in s for s in steps):
        completed = set()
        for step in workflow.steps:
            name = str(step.get("name", "")).lower()
            requires = step.get("requires")
            if requires and requires not in completed:
                findings.append(AuthFinding(
                    "AUTH-RESET-001", "Password-reset workflow contains an unmet prerequisite", "HIGH", "POTENTIAL", "password-reset",
                    {"step": step, "completed": sorted(completed)},
                    "Enforce each password-reset prerequisite on the server and invalidate prior reset state after use.",
                ))
            completed.add(name)
    return findings


def analyze_session_observation(obs: SessionObservation) -> List[AuthFinding]:
    findings: List[AuthFinding] = []
    if obs.session_before and obs.session_after_login and obs.session_before == obs.session_after_login:
        findings.append(AuthFinding(
            "AUTH-SESSION-001", "Session identifier did not rotate across authentication", "HIGH", "POTENTIAL", "session",
            {"session_before": obs.session_before, "session_after_login": obs.session_after_login},
            "Rotate the authenticated session identifier after login and privilege changes.",
        ))
    if obs.session_after_logout and obs.session_after_login == obs.session_after_logout:
        findings.append(AuthFinding(
            "AUTH-SESSION-002", "Session identifier remains unchanged after logout observation", "HIGH", "POTENTIAL", "session",
            {"session_after_login": obs.session_after_login, "session_after_logout": obs.session_after_logout},
            "Invalidate the server-side session and rotate/revoke associated tokens during logout.",
        ))
    if obs.token_before and obs.token_after and obs.token_before == obs.token_after:
        findings.append(AuthFinding(
            "AUTH-TOKEN-001", "Token value remains unchanged across authentication state transition", "MEDIUM", "POTENTIAL", "token",
            {"token_before": "present", "token_after": "present", "unchanged": True},
            "Review token issuance and rotation requirements for authentication and privilege changes.",
        ))
    return findings


def analyze_oauth_oidc(config: Dict[str, Any]) -> List[AuthFinding]:
    findings: List[AuthFinding] = []
    issuer = str(config.get("issuer", ""))
    authorization_endpoint = str(config.get("authorization_endpoint", ""))
    redirect_uris = config.get("redirect_uris") or []
    response_type = str(config.get("response_type", "code"))
    client_type = str(config.get("client_type", "public")).lower()
    state = bool(config.get("state", False))
    nonce = bool(config.get("nonce", False))
    pkce = bool(config.get("pkce", False))
    code_challenge_method = str(config.get("code_challenge_method", ""))

    for field_name, value in (("issuer", issuer), ("authorization_endpoint", authorization_endpoint)):
        if value and urlparse(value).scheme.lower() != "https":
            findings.append(AuthFinding(
                "OAUTH-HTTPS-001", f"{field_name} does not use HTTPS", "HIGH", "CONFIRMED", "oauth-oidc",
                {field_name: value}, "Use HTTPS for OAuth/OIDC issuer and authorization endpoints.",
            ))
    if response_type == "code" and not state:
        findings.append(AuthFinding(
            "OAUTH-STATE-001", "Authorization Code flow lacks state indicator", "HIGH", "POTENTIAL", "oauth-oidc",
            {"response_type": response_type}, "Use and validate a cryptographically random state value bound to the client session.",
        ))
    if client_type in {"public", "spa", "mobile"} and response_type == "code" and not pkce:
        findings.append(AuthFinding(
            "OAUTH-PKCE-001", "Public authorization-code client does not declare PKCE", "HIGH", "POTENTIAL", "oauth-oidc",
            {"client_type": client_type}, "Use PKCE with S256 for public authorization-code clients.",
        ))
    if pkce and code_challenge_method and code_challenge_method.lower() != "s256":
        findings.append(AuthFinding(
            "OAUTH-PKCE-002", "PKCE is configured with a non-S256 code challenge method", "MEDIUM", "POTENTIAL", "oauth-oidc",
            {"code_challenge_method": code_challenge_method}, "Prefer S256 and reject weaker PKCE methods where supported.",
        ))
    if "openid" in set(config.get("scopes") or []) and not nonce:
        findings.append(AuthFinding(
            "OIDC-NONCE-001", "OIDC configuration lacks nonce indicator", "MEDIUM", "POTENTIAL", "oidc",
            {"scopes": config.get("scopes") or []}, "Use and validate nonce for OIDC authentication responses.",
        ))
    for uri in redirect_uris:
        parsed = urlparse(str(uri))
        if parsed.scheme and parsed.scheme.lower() not in {"https", "http"}:
            findings.append(AuthFinding(
                "OAUTH-REDIRECT-001", "Redirect URI uses an unusual scheme", "HIGH", "POTENTIAL", "oauth-oidc",
                {"redirect_uri": uri}, "Allowlist exact redirect URIs and reject untrusted schemes/patterns.",
            ))
        if parsed.scheme.lower() == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            findings.append(AuthFinding(
                "OAUTH-REDIRECT-002", "Non-local redirect URI uses HTTP", "HIGH", "POTENTIAL", "oauth-oidc",
                {"redirect_uri": uri}, "Use HTTPS redirect URIs except narrowly scoped local development callbacks.",
            ))
    return findings


def analyze_mfa_policy(policy: Dict[str, Any]) -> List[AuthFinding]:
    findings: List[AuthFinding] = []
    if policy.get("required") and not policy.get("server_side_enforced", False):
        findings.append(AuthFinding(
            "AUTH-MFA-002", "MFA policy is declared but not marked server-side enforced", "CRITICAL", "POTENTIAL", "mfa",
            {"policy": policy}, "Enforce MFA before issuing privileged/authenticated sessions on the server.",
        ))
    if policy.get("otp_digits") is not None and int(policy.get("otp_digits")) < 6:
        findings.append(AuthFinding(
            "AUTH-MFA-003", "OTP policy uses fewer than six digits", "MEDIUM", "POTENTIAL", "mfa",
            {"otp_digits": policy.get("otp_digits")}, "Use a sufficiently strong OTP policy and enforce rate limits and lockout controls.",
        ))
    if policy.get("max_attempts") is None:
        findings.append(AuthFinding(
            "AUTH-MFA-004", "MFA policy does not declare an attempt limit", "MEDIUM", "POTENTIAL", "mfa",
            {"policy": policy}, "Enforce bounded attempts and server-side throttling for OTP verification.",
        ))
    return findings


def analyze_jwt_usage(jwt_meta: Dict[str, Any]) -> List[AuthFinding]:
    findings: List[AuthFinding] = []
    alg = str(jwt_meta.get("alg", ""))
    exp_present = bool(jwt_meta.get("exp_present", False))
    audience_validated = jwt_meta.get("audience_validated")
    issuer_validated = jwt_meta.get("issuer_validated")
    if alg.lower() == "none":
        findings.append(AuthFinding(
            "JWT-AUTH-001", "JWT usage permits an unrestricted none algorithm indicator", "CRITICAL", "POTENTIAL", "jwt",
            {"alg": alg}, "Allow only an explicitly configured and expected signing algorithm.",
        ))
    if not exp_present:
        findings.append(AuthFinding(
            "JWT-AUTH-002", "JWT usage does not declare an expiration claim", "MEDIUM", "POTENTIAL", "jwt",
            {}, "Use short-lived access tokens with explicit expiration and server-side validation.",
        ))
    if audience_validated is False:
        findings.append(AuthFinding(
            "JWT-AUTH-003", "JWT audience is present but not marked as validated", "HIGH", "POTENTIAL", "jwt",
            {}, "Validate the audience claim against the intended resource server.",
        ))
    if issuer_validated is False:
        findings.append(AuthFinding(
            "JWT-AUTH-004", "JWT issuer is present but not marked as validated", "HIGH", "POTENTIAL", "jwt",
            {}, "Validate the issuer claim against a trusted issuer configuration.",
        ))
    return findings
