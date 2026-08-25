import os, sys
os.environ['AEGISX_DATABASE_URL']='sqlite:///./aegisx_console_test.db'
sys.path.insert(0,'backend')

def test_console_module_imports():
    from app.api.console_v42 import router
    paths={getattr(r,'path',None) for r in router.routes}
    assert '/api/console/overview' in paths
    assert '/api/console/web/assessment' in paths
    assert '/api/console/csp' in paths
    assert '/api/console/jwt' in paths
    assert '/api/console/reports/{scan_id}/export/{fmt}' in paths
