from __future__ import annotations
from app.rules.engine import RuleEngine
from .runner import TestLabRunner

def build_coverage_matrix() -> dict[str, object]:
    engine = RuleEngine()
    covered = set(TestLabRunner().coverage()["rules"].keys())
    rules = engine.list_rules()
    matrix=[]
    for r in rules:
        matrix.append({
            "rule": r.key,
            "detector": r.detector,
            "covered": r.key in covered,
            "protocols": list(r.protocols),
            "family": r.family,
            "severity": r.severity,
        })
    return {
        "total_rules": len(rules),
        "covered_rules": sum(1 for x in matrix if x["covered"]),
        "uncovered_rules": sum(1 for x in matrix if not x["covered"]),
        "coverage_percent": round((sum(1 for x in matrix if x["covered"]) / len(rules) * 100), 2) if rules else 100.0,
        "matrix": matrix,
    }
