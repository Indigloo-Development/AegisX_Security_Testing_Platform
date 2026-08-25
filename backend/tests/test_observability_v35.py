from fastapi.testclient import TestClient

from app.main import app


def test_v35_capabilities():
    r = TestClient(app).get('/api/observability-v35/capabilities')
    assert r.status_code == 200
    data = r.json()
    assert data['otel_context'] is True
    assert data['siem_router'] is True
    assert data['grafana_dashboard'] is True


def test_trace_context_endpoint():
    r = TestClient(app).post('/api/observability-v35/trace', json={'name': 'scan.test', 'attributes': {'scanner': 'web'}})
    assert r.status_code == 200
    data = r.json()
    assert data['name'] == 'scan.test'
    assert data['trace_id']
    assert data['span_id']


def test_security_event_routing():
    r = TestClient(app).post('/api/observability-v35/events', json={'event_type': 'security.test', 'severity': 'HIGH'})
    assert r.status_code == 200
    data = r.json()
    assert data['event_type'] == 'security.test'
    assert data['trace_context']['trace_id']
    assert isinstance(data['delivery'], list)


def test_sink_status():
    r = TestClient(app).get('/api/observability-v35/sinks')
    assert r.status_code == 200
    assert {x['name'] for x in r.json()['sinks']} == {'log', 'webhook'}
