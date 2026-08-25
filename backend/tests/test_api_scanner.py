import json
from app.scanners.api.rest.openapi import parse_spec
from app.scanners.api.grpc.scanner import inventory_proto

def test_openapi_inventory():
    spec={'openapi':'3.0.3','servers':[{'url':'https://api.example.test'}],'paths':{'/users':{'get':{'operationId':'listUsers','parameters':[{'name':'limit','in':'query'}]}},'/users/{id}':{'delete':{'operationId':'deleteUser'}}},'components':{'securitySchemes':{'bearerAuth':{'type':'http','scheme':'bearer'}}}}
    endpoints,findings=parse_spec(spec,'https://example.test','https://example.test/openapi.json')
    assert len(endpoints)==2
    assert endpoints[0].url.startswith('https://api.example.test/')
    assert any(x['finding_key']=='API-SPEC-AUTH-SCHEME' for x in findings)

def test_proto_inventory():
    proto='''syntax = "proto3"; service UserService { rpc GetUser (GetUserRequest) returns (User); rpc DeleteUser (DeleteUserRequest) returns (Empty); }'''
    out=inventory_proto(proto)
    assert out['services']==['UserService']
    assert out['rpc_count']==2
