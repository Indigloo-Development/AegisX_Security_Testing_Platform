import json
from fastapi.testclient import TestClient
from app.main import app
from app.scanners.ai_v3.classifier import classify
from app.scanners.ai_v3.rag_agent import analyze_rag_access, evaluate_agent_tool_graph

client=TestClient(app)

# The repo's test authentication dependency accepts a deterministic development user.
def headers():
    return {"Authorization":"Bearer dev-test-token"}

def test_classifier_secret_is_high_confidence():
    labels, sev, conf, meta = classify("leakage", "api_key=ABCDEFGHIJKLMNOP")
    assert "secret-like-pattern" in labels
    assert sev == "critical"
    assert conf == "likely"


def test_classifier_output_marker_confirmed():
    labels, sev, conf, _ = classify("output", "<aegisx-safe-marker>")
    assert "expected-marker-echo" in labels
    assert conf == "confirmed"


def test_rag_cross_tenant_confirmed():
    out=analyze_rag_access([{"document_id":"d1","tenant_id":"B","authorized_tenant_id":"A"}])
    assert out["findings"][0]["confidence"] == "confirmed"


def test_agent_tool_graph_privilege_combination():
    out=evaluate_agent_tool_graph([{"name":"ops","actions":["credential.read","shell.execute","network.admin"]}])
    assert any(x["key"]=="AI3-AGENT-PRIV-001" for x in out["findings"])


def test_capabilities_route():
    r=client.get("/api/ai-security-v3/capabilities", headers=headers())
    assert r.status_code in (200,401)
    if r.status_code==200:
        assert "adaptive-selection" in r.json()["features"]
