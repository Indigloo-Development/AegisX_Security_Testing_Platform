from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    r = client.get('/health')
    assert r.status_code == 200
    assert r.json()['status'] == 'ok'

def test_security_headers():
    r = client.get('/')
    assert r.status_code == 200
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert r.headers['X-Frame-Options'] == 'DENY'
    assert r.headers['Referrer-Policy'] == 'no-referrer'
    assert r.headers['Permissions-Policy']
    assert r.headers['X-Request-ID']

def test_metrics():
    r = client.get('/metrics')
    assert r.status_code == 200
    assert 'aegisx_up 1' in r.text
