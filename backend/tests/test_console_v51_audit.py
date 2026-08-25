import os
os.environ.setdefault('AEGISX_DATABASE_URL', 'sqlite:///./aegisx_console_test_v51.db')


def test_console_v51_ai_llm_route_imports_without_runtime_nameerror():
    from app.api.console_v42 import console_ai_llm
    assert callable(console_ai_llm)


def test_console_v51_route_inventory():
    from app.api.console_v42 import router
    paths={r.path for r in router.routes}
    required={
        '/api/console/web/assessment','/api/console/web/authenticated',
        '/api/console/api/rest','/api/console/api/graphql','/api/console/api/grpc','/api/console/api/soap',
        '/api/console/api/swagger','/api/console/api/json-code','/api/console/csp','/api/console/csp/directives','/api/console/jwt',
        '/api/console/sca/repository','/api/console/sca/url','/api/console/sca/manifest',
        '/api/console/ai/llm','/api/console/ai/rag','/api/console/ai/agent','/api/console/ai/redteam','/api/console/ai/mcp',
        '/api/console/findings','/api/console/findings/{finding_id}','/api/console/overview',
        '/api/console/reports/{scan_id}','/api/console/reports/{scan_id}/export/{fmt}'
    }
    assert required.issubset(paths)


def test_console_v51_taxonomy_mapping_is_not_generic():
    from types import SimpleNamespace
    from app.api.console_v42 import _effective_cwe, _effective_owasp
    fake_scan=SimpleNamespace(scanner_family='web')
    sql=SimpleNamespace(title='SQL Injection',category='Injection',scan=fake_scan,cwe='CWE-16',owasp_mapping='A02:2025 - Security Misconfiguration')
    assert _effective_cwe(sql) == 'CWE-89'
    assert _effective_owasp(sql).startswith('A05:2025')
