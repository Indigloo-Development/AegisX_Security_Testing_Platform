
from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_ai_start_route_exists():
    r=client.post('/api/console/ai/start',json={'kind':'llm','target_url':'http://127.0.0.1:1','provider':'generic-json'})
    assert r.status_code in (200,503)
