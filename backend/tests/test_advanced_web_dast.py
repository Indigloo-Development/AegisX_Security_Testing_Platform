from app.scanners.web.advanced.models import PageContext
from app.scanners.web.advanced.analyzers import analyze_page
from app.scanners.web.advanced.discovery import discover_api_routes, discover_parameters, fingerprint_technologies, discover_security_artifacts
from app.scanners.web.advanced.report import summarize_findings, rule_catalog

def test_advanced_header_rules():
    ctx = PageContext(
        url="https://example.test/account?q=x",
        status_code=200,
        headers={
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.test *",
            "set-cookie": "session=abc; Path=/",
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
            "server": "ExampleServer/1.2",
        },
        body='<html><form><input name="password"></form><script src="http://cdn.example.test/a.js"></script><script>//# sourceMappingURL=app.js.map</script></html>',
        content_type="text/html",
    )
    findings = analyze_page(ctx)
    keys = {f["finding_key"] for f in findings}
    assert "WEB-CSP-002" in keys
    assert "WEB-CSP-004" in keys
    assert "WEB-CORS-002" in keys
    assert "WEB-COOKIE-001" in keys
    assert "WEB-COOKIE-002" in keys
    assert "WEB-TRANSPORT-001" in keys
    assert "WEB-APP-001" in keys

def test_discovery_and_fingerprinting():
    url = "https://example.test/search?q=one"
    body = '<script src="/_next/static/app.js"></script><script>fetch("/api/users")</script><form action="/search"><input name="q"></form>'
    params = discover_parameters(url, body)
    assert any(x["name"] == "q" for x in params)
    routes = discover_api_routes(url, body)
    assert "https://example.test/api/users" in routes
    tech = fingerprint_technologies(url, {"server": "nginx"}, body)
    assert any(x["name"] == "Next.js" for x in tech)
    artifacts = discover_security_artifacts(url, body)
    assert "https://example.test/robots.txt" in artifacts

def test_rule_catalog_and_summary():
    catalog = rule_catalog()
    assert len(catalog) >= 25
    findings = [{"severity":"high","category":"Security Headers","owasp":["A02:2025"],"cwe":["CWE-693"]}]
    summary = summarize_findings(findings)
    assert summary["total"] == 1
    assert summary["severity"]["high"] == 1
    assert summary["owasp"]["A02:2025"] == 1
