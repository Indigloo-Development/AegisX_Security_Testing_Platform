from app.reporting.engine_v26 import build_report, to_csv_report, to_sarif, to_html_report

FINDINGS = [
    {"finding_key":"AX-1","title":"Broken Access Control","severity":"high","confidence":"confirmed","category":"Authorization","endpoint":"/admin","description":"role mismatch","remediation":"enforce server-side authorization","evidence":{"timestamp":"2026-08-19T10:00:00Z"}},
    {"finding_key":"AX-2","title":"LLM prompt injection","severity":"critical","confidence":"potential","category":"LLM","endpoint":"/chat","description":"injection indicator","remediation":"add instruction boundary controls","evidence":{"observed_at":"2026-08-19T10:01:00Z"}},
]

def test_build_report_summary_and_compliance():
    r = build_report(FINDINGS)
    assert r["summary"]["total"] == 2
    assert r["summary"]["severity"]["critical"] == 1
    assert any("OWASP LLM Top 10" in x["controls"] for x in r["compliance_crosswalk"])

def test_sarif_shape():
    s = to_sarif(FINDINGS)
    assert s["version"] == "2.1.0"
    assert len(s["runs"][0]["results"]) == 2

def test_csv_and_html_outputs():
    c = to_csv_report(FINDINGS)
    h = to_html_report(build_report(FINDINGS))
    assert "finding_key" in c and "AX-1" in c
    assert "AegisX Security Report" in h

def test_evidence_timeline_sorted():
    r = build_report(FINDINGS)
    assert r["evidence_timeline"][0]["finding_key"] == "AX-1"
