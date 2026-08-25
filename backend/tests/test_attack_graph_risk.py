from app.intelligence.attack_graph import build_attack_graph
from app.intelligence.risk import advanced_risk, remediation_priorities


def sample_findings():
    return [
        {"id": 1, "finding_key": "AUTH-1", "title": "Authentication weakness", "severity": "high", "confidence": "confirmed", "category": "Authentication", "endpoint": "https://app.test/login", "remediation": "Harden authentication."},
        {"id": 2, "finding_key": "API-ACL-1", "title": "Broken access control", "severity": "high", "confidence": "confirmed", "category": "Authorization", "endpoint": "https://app.test/api/admin", "remediation": "Enforce authorization."},
        {"id": 3, "finding_key": "DATA-1", "title": "Sensitive data disclosure", "severity": "medium", "confidence": "likely", "category": "Data Exposure", "endpoint": "https://app.test/api/data", "remediation": "Minimize sensitive data exposure."},
        {"id": 4, "finding_key": "INJ-1", "title": "SQL Injection", "severity": "critical", "confidence": "confirmed", "category": "Injection", "endpoint": "https://app.test/search", "remediation": "Use parameterized queries."},
    ]


def test_attack_graph_builds_nodes_edges_and_paths():
    graph = build_attack_graph(sample_findings())
    assert graph["node_count"] >= 5
    assert graph["edge_count"] >= 1
    assert graph["path_count"] >= 1
    assert any(p["risk"] in {"high", "critical"} for p in graph["paths"])


def test_advanced_risk_increases_for_attack_paths():
    findings = sample_findings()
    graph = build_attack_graph(findings)
    risk = advanced_risk(findings, graph)
    plain = advanced_risk(findings, {"paths": []})
    assert risk["score"] >= plain["score"]
    assert risk["attack_path_count"] >= 1
    assert risk["overall_risk"] in {"high", "critical"}


def test_priorities_promote_attack_path_nodes():
    findings = sample_findings()
    graph = build_attack_graph(findings)
    priorities = remediation_priorities(findings, graph)
    assert priorities
    assert priorities[0]["priority_score"] >= priorities[-1]["priority_score"]
