from app.intelligence.brain import analyze, build_scan_plan, deduplicate, risk_assessment


def test_deduplicate_prefers_higher_severity():
    findings = [
        {"finding_key":"X-1","title":"Same","severity":"low","category":"Web","endpoint":"https://a/x","description":"a"},
        {"finding_key":"X-1","title":"Same","severity":"high","category":"Web","endpoint":"https://a/x","description":"b"},
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0]["severity"] == "high"


def test_scan_plan_deep_rag_agent():
    plan = build_scan_plan("rag-agent", "deep")
    assert "ai" in plan["recommended_scanners"]
    assert "rag" in plan["recommended_scanners"]
    assert "agent" in plan["recommended_scanners"]
    assert "csp" in plan["recommended_scanners"]


def test_risk_assessment():
    r = risk_assessment([
        {"finding_key":"A","title":"Critical","severity":"critical","category":"Web","endpoint":"https://a"},
        {"finding_key":"B","title":"High","severity":"high","category":"API","endpoint":"https://a/api"},
    ])
    assert r["overall_risk"] == "critical"
    assert r["critical"] == 1


def test_analyze_returns_correlation_and_plan():
    data = analyze([
        {"finding_key":"AUTH-1","title":"Authentication failure","severity":"high","category":"Authentication","endpoint":"https://a/login"},
        {"finding_key":"API-1","title":"Broken access control","severity":"high","category":"Authorization","endpoint":"https://a/api/admin"},
        {"finding_key":"CSP-1","title":"Weak CSP","severity":"medium","category":"CSP","endpoint":"https://a/"},
    ], target_type="web", profile="deep")
    assert data["finding_count"] == 3
    assert data["risk"]["overall_risk"] == "high"
    assert data["attack_surface_correlations"]
    assert data["scan_plan"]["recommended_scanners"]
