from app.scanners.api.fuzzing.engine import APIFuzzEngine, observation


def test_openapi_cases_are_bounded_and_typed():
    doc = {
        "paths": {
            "/users": {
                "get": {
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                    ]
                }
            }
        }
    }
    result = APIFuzzEngine().generate_openapi_cases(doc, max_cases=20)
    assert len(result.cases) == 7
    assert all(c.safe for c in result.cases)


def test_differential_status_and_body():
    engine = APIFuzzEngine()
    result = engine.compare_observations([
        observation("user", 200, "application/json", 10, '{"a":1}'),
        observation("manager", 403, "application/json", 10, '{"a":1}'),
    ])
    assert result["differential"] is True
    assert any(f["rule"] == "API-FUZZ-DIFF-STATUS" for f in result["findings"])


def test_workflow_missing_prerequisite():
    result = APIFuzzEngine().build_workflow([
        {"state": "authenticated", "method": "GET", "path": "/me"},
        {"state": "changed-email", "method": "POST", "path": "/email", "requires": ["email-verified"]},
    ])
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule"] == "API-FLOW-STATE-001"
