from app.scanners.web.dom_analysis_v18 import analyze_dom_dataflow
from app.scanners.websocket.analyzer_v18 import analyze_handshake, analyze_message


def test_dom_source_sink_flow():
    js = "const q = location.search; el.innerHTML = q;"
    flows = analyze_dom_dataflow(js)
    assert any(f.source == "location.search" and f.sink == "innerHTML" for f in flows)


def test_dom_safe_no_flow():
    assert analyze_dom_dataflow("const x = encodeURIComponent(location.search);") == []


def test_websocket_handshake_tls_and_origin():
    findings = analyze_handshake(url="ws://example.test/socket", request_headers={}, response_headers={"Sec-WebSocket-Accept": "x"})
    keys = {f.key for f in findings}
    assert "WS-TLS-001" in keys
    assert "WS-ORIGIN-001" in keys


def test_websocket_message_and_auth_metadata():
    findings = analyze_message(message='<script>alert(1)</script>', metadata={"auth_required": False, "sensitive_action": True})
    keys = {f.key for f in findings}
    assert keys == {"WS-OUTPUT-001", "WS-AUTHZ-001"}
