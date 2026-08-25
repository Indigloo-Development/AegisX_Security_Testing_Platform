from app.scanners.web.discovery import extract_discovery
from app.scanners.web.passive_rules import analyze_headers


def test_csp_missing_and_security_headers():
    findings = analyze_headers("https://example.test", {"content-type": "text/html"}, 200)
    keys = {x["finding_key"] for x in findings}
    assert "WEB-CSP-001" in keys
    assert "WEB-HDR-001" in keys
    assert "WEB-CLICKJACK-001" in keys


def test_discovery_extracts_same_origin_links_and_forms():
    html = """
    <html><body>
      <a href='/users'>Users</a>
      <a href='https://example.test/admin'>Admin</a>
      <a href='https://other.test/x'>Other</a>
      <form action='/login' method='post'></form>
      <script src='/app.js'></script>
    </body></html>
    """
    urls, forms, scripts = extract_discovery("https://example.test/", html)
    assert "https://example.test/users" in urls
    assert "https://example.test/admin" in urls
    assert "https://other.test/x" not in urls
    assert forms[0]["action"] == "https://example.test/login"
    assert "https://example.test/app.js" in scripts
