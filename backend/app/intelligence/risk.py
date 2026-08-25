from __future__ import annotations

from typing import Any, Iterable

SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONFIDENCE = {"confirmed": 1.0, "likely": 0.8, "potential": 0.55, "informational": 0.3}


def _items(findings: Iterable[Any]) -> list[dict[str, Any]]:
    out = []
    for f in findings:
        if isinstance(f, dict):
            out.append(dict(f))
        else:
            out.append({k: getattr(f, k, None) for k in ("id", "finding_key", "title", "severity", "confidence", "category", "endpoint", "evidence", "remediation")})
    return out


def advanced_risk(findings: Iterable[Any], attack_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    items = _items(findings)
    graph = attack_graph or {"paths": []}
    paths = graph.get("paths", [])
    base = 0.0
    weighted = []
    for f in items:
        sev = str(f.get("severity", "info")).lower()
        conf = str(f.get("confidence", "potential")).lower()
        score = SEVERITY.get(sev, 1) * CONFIDENCE.get(conf, 0.55) * 6
        weighted.append({"finding_key": f.get("finding_key"), "score": round(score, 2), "severity": sev, "confidence": conf})
        base += score
    path_bonus = sum(14 if p.get("risk") == "critical" else 9 for p in paths)
    attack_path_score = min(40, path_bonus)
    final = min(100, round(base + attack_path_score, 2))
    if final >= 80: overall = "critical"
    elif final >= 55: overall = "high"
    elif final >= 30: overall = "medium"
    elif final > 0: overall = "low"
    else: overall = "info"
    weighted.sort(key=lambda x: x["score"], reverse=True)
    return {
        "score": final,
        "overall_risk": overall,
        "base_score": round(min(100, base), 2),
        "attack_path_bonus": attack_path_score,
        "attack_path_count": len(paths),
        "prioritized_findings": weighted,
        "explanation": f"Advanced risk combines severity/confidence with {len(paths)} candidate attack path(s). Paths are correlation candidates and require validation before exploitation claims."
    }


def remediation_priorities(findings: Iterable[Any], attack_graph: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items = _items(findings)
    graph = attack_graph or {"paths": []}
    path_nodes = {n for p in graph.get("paths", []) for n in p.get("nodes", [])}
    results = []
    for f in items:
        key = str(f.get("finding_key"))
        severity = SEVERITY.get(str(f.get("severity", "info")).lower(), 1)
        priority = severity * 10 + (15 if key in path_nodes else 0) + (10 if str(f.get("confidence", "potential")).lower() == "confirmed" else 0)
        results.append({"finding_key": key, "title": f.get("title"), "priority_score": priority, "reason": "On a candidate attack path" if key in path_nodes else "Severity/confidence based priority", "remediation": f.get("remediation")})
    return sorted(results, key=lambda x: (-x["priority_score"], x["finding_key"]))
