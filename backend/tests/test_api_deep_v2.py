from app.scanners.api.deep.engine import APIDeepEngine

def test_openapi_deep_analysis():
    doc = {
        "openapi": "3.0.3",
        "paths": {
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                }
            },
            "/search": {
                "get": {
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                    ],
                    "security": [{"bearerAuth": []}],
                }
            },
        },
        "components": {"schemas": {"User": {"type": "object", "additionalProperties": True}}},
    }
    out = APIDeepEngine().analyze_openapi(doc, ["admin", "user"])
    keys = {x["finding_key"] for x in out["findings"]}
    assert "API-AUTH-001" in keys
    assert "API-SCHEMA-002" in keys
    assert "API-RES-001" in keys
    assert len(out["authorization_matrix"]) >= 2

def test_graphql_depth_and_mutation():
    schema = {"types": [{"name": "Query", "fields": [{"name": str(i)} for i in range(12)]}, {"name": "Mutation", "fields": [{"name": "deleteUser"}]}]}
    out = APIDeepEngine().analyze_graphql(schema)
    keys = {x["finding_key"] for x in out["findings"]}
    assert "API-GQL-001" in keys
    assert "API-GQL-002" in keys

def test_soap_and_grpc():
    assert APIDeepEngine().analyze_soap("<!DOCTYPE definitions><definitions/>")["findings"][0]["confidence"] == "confirmed"
    assert APIDeepEngine().analyze_grpc('import "grpc/reflection/v1alpha/reflection.proto"; service App {}', True)["findings"]
