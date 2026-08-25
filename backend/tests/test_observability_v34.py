from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_capabilities():
    r = client.get('/api/observability-v34/capabilities')
    assert r.status_code == 200
    data = r.json()
    assert data['local_metrics'] is True
    assert data['external_collector_required'] is False


def test_local_metrics_endpoint():
    r = client.get('/metrics')
    assert r.status_code == 200
    assert 'aegisx_up 1' in r.text


def test_health():
    r = client.get('/health')
    assert r.status_code == 200
