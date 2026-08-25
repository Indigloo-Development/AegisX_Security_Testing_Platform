import asyncio
from app.commercial.deep_dast import DeepAuthenticatedDAST, DeepDASTRequest, RetestRequest, RoleProfile


def test_passive_header_rules():
    fs = DeepAuthenticatedDAST._passive_headers({})
    assert {x['type'] for x in fs} == {'missing_csp','missing_hsts','missing_nosniff'}


def test_sql_signature_detection():
    assert DeepAuthenticatedDAST._sql_error('PostgreSQL ERROR: syntax error')
    assert not DeepAuthenticatedDAST._sql_error('normal application response')


def test_url_normalization_same_origin():
    f = DeepAuthenticatedDAST._normalize
    assert f('https://example.com/a','/b#x','example.com',True) == 'https://example.com/b'
    assert f('https://example.com/a','https://evil.example/b','example.com',True) is None


def test_reflected_canary():
    assert DeepAuthenticatedDAST._reflected_canary('abc AEGISX_DAST_CANARY_9f3d xyz')
    assert not DeepAuthenticatedDAST._reflected_canary('abc')


def test_deep_request_defaults():
    r = DeepDASTRequest(target_url='https://example.com', roles=[RoleProfile(name='user')])
    assert r.max_pages == 25
    assert r.roles[0].name == 'user'


def test_retest_model():
    r = RetestRequest(target_url='https://example.com', finding_type='missing_csp', original_status=200)
    assert r.finding_type == 'missing_csp'

