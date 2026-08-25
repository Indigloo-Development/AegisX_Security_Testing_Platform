from app.commercial.authentication_v15 import (
    AuthWorkflow, SessionObservation, analyze_jwt_usage, analyze_login_workflow,
    analyze_mfa_policy, analyze_oauth_oidc, analyze_session_observation,
)


def ids(findings):
    return {f.rule_id for f in findings}


def test_login_mfa_and_reset_workflow():
    fs = analyze_login_workflow(AuthWorkflow(
        "login-reset",
        [
            {"name": "login"},
            {"name": "password reset", "requires": "reset-token-verified"},
        ],
        requires_mfa=True,
    ))
    assert "AUTH-MFA-001" in ids(fs)
    assert "AUTH-FLOW-001" in ids(fs)
    assert "AUTH-RESET-001" in ids(fs)


def test_session_rotation_and_logout():
    fs = analyze_session_observation(SessionObservation("same", "same", None, "same"))
    assert "AUTH-SESSION-001" in ids(fs)
    assert "AUTH-SESSION-002" in ids(fs)


def test_oauth_public_client_requires_pkce_state():
    fs = analyze_oauth_oidc({
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "client_type": "public",
        "response_type": "code",
        "state": False,
        "pkce": False,
        "scopes": ["openid"],
        "nonce": False,
        "redirect_uris": ["http://evil.example/callback"],
    })
    assert "OAUTH-STATE-001" in ids(fs)
    assert "OAUTH-PKCE-001" in ids(fs)
    assert "OIDC-NONCE-001" in ids(fs)
    assert "OAUTH-REDIRECT-002" in ids(fs)


def test_mfa_policy():
    fs = analyze_mfa_policy({"required": True, "server_side_enforced": False, "otp_digits": 4})
    assert "AUTH-MFA-002" in ids(fs)
    assert "AUTH-MFA-003" in ids(fs)
    assert "AUTH-MFA-004" in ids(fs)


def test_jwt_usage():
    fs = analyze_jwt_usage({"alg": "none", "exp_present": False, "audience_validated": False, "issuer_validated": False})
    assert {"JWT-AUTH-001", "JWT-AUTH-002", "JWT-AUTH-003", "JWT-AUTH-004"} <= ids(fs)
