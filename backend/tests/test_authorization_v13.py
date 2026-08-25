from app.commercial.authorization_v13 import Principal, AccessObservation, build_matrix, compare_observations, analyze_workflow


def test_matrix():
    out = build_matrix([Principal("u1", "user", "t1")], [{"path": "/api/items/{id}", "methods": ["GET"], "allowed_roles": ["admin"]}])
    assert out["principals"] == 1
    assert out["matrix"][0]["endpoint"] == "/api/items/{id}"


def test_authorization_differential_observation():
    obs = [
        AccessObservation("admin", "admin", "t1", "/api/items/1", "GET", "1", 200, 500, "allow"),
        AccessObservation("user", "user", "t1", "/api/items/1", "GET", "1", 200, 490, "deny"),
    ]
    findings = compare_observations(obs)
    assert any(f.rule_id == "AUTHZ-DIFF-001" for f in findings)


def test_tenant_isolation_observation():
    obs = [
        AccessObservation("a", "user", "t1", "/api/items/1", "GET", "1", 200, 500, "allow"),
        AccessObservation("b", "user", "t2", "/api/items/1", "GET", "1", 200, 500, "allow"),
    ]
    findings = compare_observations(obs)
    assert any(f.rule_id == "AUTHZ-TENANT-001" for f in findings)


def test_workflow_prerequisite():
    out = analyze_workflow([
        {"name": "register", "completed": []},
        {"name": "reset", "requires": "verify_email"},
    ])
    assert out["findings"]
