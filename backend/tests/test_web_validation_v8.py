from app.scanners.web.validation import (
    analyze_reflection_and_dom, analyze_injection_errors, analyze_csrf_and_sessions,
    analyze_session_rotation, analyze_workflow, WorkflowStep,
)

def test_reflection_and_dom_sink_source():
    body = '<script>const x=location.hash; el.innerHTML=x;</script>'
    fs = analyze_reflection_and_dom(body, 'https://example.test/?q=hello')
    assert any(f['finding_key'] == 'WEB-XSS-DOM-001' for f in fs)

def test_reflected_value_is_not_confirmed_xss():
    fs = analyze_reflection_and_dom('<html>hello</html>', 'https://example.test/?q=hello')
    assert fs and fs[0]['confidence'] == 'potential'

def test_sql_and_command_errors_are_potential():
    fs = analyze_injection_errors('You have an error in your SQL syntax; /bin/sh: bad command', 'https://example.test')
    keys = {f['finding_key'] for f in fs}
    assert 'WEB-SQLI-ERROR-001' in keys
    assert 'WEB-CMD-ERROR-001' in keys

def test_csrf_candidate():
    html = '<form method="post"><input name="email"></form>'
    fs = analyze_csrf_and_sessions(html=html, response_headers={}, request_url='https://example.test/change')
    assert fs and fs[0]['finding_key'] == 'WEB-CSRF-001'

def test_session_rotation_observation():
    fs = analyze_session_rotation(['session=abc'], ['session=xyz'])
    assert fs and fs[0]['finding_key'] == 'WEB-SESSION-001'

def test_business_workflow_state_transition():
    result = analyze_workflow([
        WorkflowStep('read', 'GET', '/account', requires_auth=True),
        WorkflowStep('change', 'GET', '/account/email', state_change=True, requires_auth=True),
    ])
    assert any(f['finding_key'] == 'WEB-BL-001' for f in result.findings)
