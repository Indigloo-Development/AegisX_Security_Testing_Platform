from app.rules.engine import RuleEngine
from app.rules.models import ScanContext


def test_web_xss_and_ssrf_flags():
    e = RuleEngine()
    ctx = ScanContext(url="https://example.test/search?q=x", protocol="web", metadata={
        "xss_reflection_context": True,
        "ssrf_candidate": True,
    })
    keys = ["WEB-XSS-001", "WEB-SSRF-001"]
    findings = e.evaluate(ctx, keys)
    assert {f.rule_key for f in findings} == set(keys)


def test_api_authorization_flags():
    e = RuleEngine()
    ctx = ScanContext(url="https://api.example.test/users/1", protocol="api", metadata={
        "cross_tenant_object_read": True,
        "mass_assignment_observed": True,
        "function_access_mismatch": True,
    })
    findings = e.evaluate(ctx, ["API-BOLA-002", "API-BOPLA-002", "API-BFLA-001"])
    assert {f.rule_key for f in findings} == {"API-BOLA-002", "API-BOPLA-002", "API-BFLA-001"}


def test_auth_and_business_logic_flags():
    e = RuleEngine()
    ctx = ScanContext(url="https://example.test/reset", protocol="web", metadata={
        "oauth_state_missing": True,
        "prerequisite_bypass": True,
        "session_fixation_indicator": True,
    })
    findings = e.evaluate(ctx, ["AUTH-OAUTH-002", "BL-STATE-002", "AUTH-SESSION-001"])
    assert {f.rule_key for f in findings} == {"AUTH-OAUTH-002", "BL-STATE-002", "AUTH-SESSION-001"}


def test_catalog_size_and_mappings():
    e = RuleEngine()
    keys = {r.key for r in e.list_rules()}
    assert len(keys) >= 170
    for key in ["WEB-XSS-001", "API-BOLA-002", "GQL-AUTH-001", "AUTH-OAUTH-003", "BL-RACE-001"]:
        r = e.get_rule(key)
        assert r.detector == "wave17"
        assert r.tags
