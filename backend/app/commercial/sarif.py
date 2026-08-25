from __future__ import annotations
from typing import Any

def to_sarif(findings: list[dict[str, Any]], tool_name: str = "AegisX") -> dict[str, Any]:
    results = []
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        level = "error" if sev in {"critical", "high"} else "warning" if sev == "medium" else "note"
        results.append({
            "ruleId": f.get("finding_key", "AEGISX-FINDING"),
            "level": level,
            "message": {"text": f.get("title", "Security finding")},
            "properties": {"severity": sev, "confidence": f.get("confidence", "unknown"), "category": f.get("category", "")},
            "locations": ([{"physicalLocation": {"artifactLocation": {"uri": f["endpoint"]}}}] if f.get("endpoint") else []),
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool_name, "version": "55.0.0"}}, "results": results}]}
