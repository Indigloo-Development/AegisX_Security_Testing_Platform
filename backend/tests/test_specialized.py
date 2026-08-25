from app.scanners.specialized.analyzers import analyze_csp, audit_jwt, analyze_cors, analyze_cookies, analyze_oauth_oidc


def test_csp_analyzer():
    result = analyze_csp("default-src 'self'; script-src 'self' 'unsafe-inline'; img-src *")
    assert result["present"] is True
    assert any(f["finding_key"] == "CSP-004" for f in result["findings"])


def test_csp_missing():
    result = analyze_csp(None)
    assert result["present"] is False
    assert result["findings"][0]["finding_key"] == "CSP-001"


def test_jwt_audit():
    token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9.signature"
    result=audit_jwt(token)
    assert result["valid_structure"] is True
    assert result["algorithm"] == "HS256"
    assert any(f["finding_key"] == "JWT-005" for f in result["findings"])


def test_jwt_none():
    token="eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.signature"
    result=audit_jwt(token)
    assert any(f["finding_key"] == "JWT-003" for f in result["findings"])


def test_cors_and_cookies():
    cors=analyze_cors({"access-control-allow-origin":"*", "access-control-allow-credentials":"true"})
    assert cors["findings"][0]["severity"] == "high"
    cookies=analyze_cookies({"set-cookie":"session=abc; Path=/"})
    assert len(cookies["findings"]) == 3


def test_oauth_https_check():
    result=analyze_oauth_oidc("http://example.com/authorize")
    assert result["findings"][0]["finding_key"] == "OAUTH-001"
