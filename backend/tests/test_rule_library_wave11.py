from app.rules.engine import RuleEngine
from app.rules.models import ScanContext


def test_security_headers_and_transport_rules():
    e = RuleEngine()
    ctx = ScanContext(url="http://example.test", protocol="web", headers={"server": "nginx"}, body="")
    keys = ["WEB-HDR-004", "WEB-HDR-005", "WEB-HDR-006", "WEB-HDR-007", "WEB-TRANS-001"]
    out = e.evaluate(ctx, keys)
    assert {x.rule_key for x in out} == set(keys)


def test_open_redirect_and_sensitive_data():
    e = RuleEngine()
    ctx = ScanContext(
        url="https://example.test/login?next=https://evil.example",
        protocol="web",
        status_code=302,
        headers={"location": "https://evil.example"},
        body='{"access_token":"REDACTED"}',
        parameters=[{"name": "next"}],
    )
    out = e.evaluate(ctx, ["WEB-REDIR-001", "WEB-DATA-001"])
    assert {x.rule_key for x in out} == {"WEB-REDIR-001", "WEB-DATA-001"}


def test_api_authorization_and_graphql():
    e = RuleEngine()
    ctx = ScanContext(url="https://api.example.test/graphql", protocol="api", metadata={
        "cross_tenant_read": True,
        "privileged_action_low_role": True,
        "introspection_public": True,
    })
    out = e.evaluate(ctx, ["API-AUTHZ-003", "API-AUTHZ-004", "API-GQL-003"])
    assert len(out) == 3
    assert all(x.confidence in {"confirmed", "high"} for x in out)


def test_ai_and_sca():
    e = RuleEngine()
    ai = ScanContext(url="https://llm.example/api/chat", protocol="ai", metadata={
        "prompt_injection_success": True,
        "system_prompt_disclosed": True,
        "cross_tenant_retrieval": True,
    })
    ai_out = e.evaluate(ai, ["AI-LLM-001", "AI-LLM-002", "AI-RAG-002"])
    assert {x.rule_key for x in ai_out} == {"AI-LLM-001", "AI-LLM-002", "AI-RAG-002"}

    sca = ScanContext(url="component://requests", protocol="sca", metadata={
        "cve_id": "CVE-2026-0001", "kev": True, "epss": 0.92, "reachable": True,
    })
    sca_out = e.evaluate(sca, ["SCA-001", "SCA-002", "SCA-003", "SCA-004"])
    assert {x.rule_key for x in sca_out} == {"SCA-001", "SCA-002", "SCA-003", "SCA-004"}
