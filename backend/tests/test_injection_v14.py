from app.rules.engine import RuleEngine
from app.rules.models import ScanContext
from app.rules.injection import create_oast_token


def test_sql_ssti_and_xxe_indicators():
    e = RuleEngine()
    ctx = ScanContext(
        url="https://app.example.test/search",
        protocol="web",
        content_type="application/xml",
        body="SQL syntax error; Jinja2 template syntax error",
        metadata={"controlled_input_variation": True, "controlled_template_probe": True, "external_entity_processing": True},
    )
    out = e.evaluate(ctx, ["INJ-SQL-001", "INJ-SSTI-001", "INJ-XXE-001"])
    assert {x.rule_key for x in out} == {"INJ-SQL-001", "INJ-SSTI-001", "INJ-XXE-001"}


def test_ssrf_oast_correlation():
    token = create_oast_token("scan-123")
    e = RuleEngine()
    ctx = ScanContext(
        url="https://app.example.test/fetch",
        protocol="web",
        parameters=[{"name": "url"}],
        metadata={"server_side_fetch_candidate": True, "oast_token": token, "oast_callback_observed": True},
    )
    out = e.evaluate(ctx, ["INJ-SSRF-001", "INJ-SSRF-002"])
    assert {x.rule_key for x in out} == {"INJ-SSRF-001", "INJ-SSRF-002"}


def test_other_injection_families():
    e = RuleEngine()
    ctx = ScanContext(url="https://api.example.test", protocol="api", body="LDAP error: invalid filter; XPath error", metadata={"header_injection_indicator": True, "ldap_error_observed": True, "xpath_error_observed": True})
    out = e.evaluate(ctx, ["INJ-LDAP-001", "INJ-XPATH-001", "INJ-CRLF-001"])
    assert {x.rule_key for x in out} == {"INJ-LDAP-001", "INJ-XPATH-001", "INJ-CRLF-001"}
