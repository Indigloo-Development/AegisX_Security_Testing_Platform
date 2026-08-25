from app.scanners.protocols import GraphQLValidator, SOAPValidator, GRPCValidator, WebDeepValidator


def test_graphql_deep_validator():
    issues = GraphQLValidator().analyze({
        "metadata": {"introspection_public": True},
        "query": {"users": {"authorization": False}},
        "mutation": {"deleteUser": {"authorization": False}},
    })
    keys = {i.key for i in issues}
    assert {"GQL-001", "GQL-002", "GQL-003", "GQL-004", "GQL-005", "GQL-006"} <= keys


def test_graphql_safe_schema_no_confirmed_auth_findings():
    issues = GraphQLValidator().analyze({
        "metadata": {"depth_limit": 8, "complexity_limit": 100, "alias_limit": 10},
        "query": {"users": {"authorization": True}},
        "mutation": {"deleteUser": {"authorization": True}},
    })
    assert not [i for i in issues if i.confidence == "confirmed"]


def test_soap_xxe_and_limits():
    xml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body/></soap:Envelope>'
    issues = SOAPValidator().analyze(xml, {"external_entities_enabled": True, "schema_validation": False})
    assert {i.key for i in issues} >= {"SOAP-001", "SOAP-002", "SOAP-003", "SOAP-004"}


def test_soap_https_schema_controls():
    issues = SOAPValidator().analyze('<soap:Envelope><soap:Body/></soap:Envelope>', {
        "url": "https://api.example/soap", "schema_validation": True, "entity_expansion_limit": 64,
    })
    assert not issues


def test_grpc_protocol_controls():
    proto = 'syntax = "proto3"; service UserService { rpc GetUser (GetUserRequest) returns (User); }'
    issues = GRPCValidator().analyze(proto, {
        "plaintext_transport": True, "reflection_public": True, "auth_required": False,
    })
    assert {i.key for i in issues} == {"GRPC-001", "GRPC-002", "GRPC-005"}


def test_grpc_inventory():
    proto = 'syntax = "proto3"; service UserService { rpc GetUser (Req) returns (User); rpc DeleteUser (Req) returns (User); }'
    issues = GRPCValidator().analyze(proto, {"auth_required": True})
    assert not [i for i in issues if i.key in {"GRPC-003", "GRPC-004"}]


def test_web_deep_validator_error_and_cookie_controls():
    issues = WebDeepValidator().analyze(
        url="https://app.example/login",
        status=500,
        headers={"set-cookie": "session=abc", "location": "https://evil.example"},
        body="Traceback\nSQLSTATE[42000]: syntax error",
        parameters=[{"name": "next", "location": "query"}],
    )
    keys = {i.key for i in issues}
    assert {"WEB-VAL-001", "WEB-VAL-002", "WEB-VAL-007", "WEB-VAL-008", "WEB-VAL-009"} <= keys


def test_web_deep_validator_mixed_content_and_redirect():
    issues = WebDeepValidator().analyze(
        url="https://app.example/",
        status=302,
        headers={"location": "https://external.example"},
        body='<script src="http://cdn.example/app.js"></script>',
    )
    assert {i.key for i in issues} == {"WEB-VAL-005", "WEB-VAL-006"}
