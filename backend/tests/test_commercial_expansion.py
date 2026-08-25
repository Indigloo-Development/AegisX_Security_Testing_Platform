from app.commercial.models import AuthProfile, ScanPolicy
from app.commercial.auth_context import build_auth_headers
from app.commercial.risk import score_finding
from app.commercial.sarif import to_sarif
from app.commercial.threat_intel import enrich

def test_auth_context_masks_and_builds():
    p = AuthProfile(name="qa", bearer_token="secret-token", cookies={"sid": "abc"})
    assert build_auth_headers(p)["Authorization"] == "Bearer secret-token"
    assert p.sanitized()["cookies"]["sid"] == "***"

def test_policy_validation():
    ScanPolicy().validate()
    try:
        ScanPolicy(max_requests=0).validate()
        assert False
    except ValueError:
        assert True

def test_risk_scoring():
    r = score_finding({"severity": "high", "confidence": "confirmed", "evidence": {"x": 1}})
    assert r["score"] >= 70
    assert r["risk_level"] == "critical"

def test_sarif():
    s = to_sarif([{"finding_key": "X", "title": "Test", "severity": "high", "confidence": "confirmed", "endpoint": "https://example.com"}])
    assert s["version"] == "2.1.0"
    assert s["runs"][0]["results"][0]["ruleId"] == "X"

def test_offline_intel():
    findings = enrich({"ecosystem": "npm", "name": "lodash", "version": "4.17.15"})
    assert findings and findings[0]["identifier"] == "CVE-2019-10744"
