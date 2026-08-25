from __future__ import annotations
from typing import Any
SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def score_finding(finding: dict[str, Any]) -> dict[str, Any]:
    base = SEV.get(str(finding.get("severity", "info")).lower(), 0) * 20
    confidence = {"unknown": 0, "potential": 5, "likely": 10, "confirmed": 15}.get(str(finding.get("confidence", "unknown")).lower(), 0)
    evidence = 10 if finding.get("evidence") else 0
    score = min(100, base + confidence + evidence)
    if score >= 85: level = "critical"
    elif score >= 65: level = "high"
    elif score >= 40: level = "medium"
    elif score >= 20: level = "low"
    else: level = "info"
    return {"score": score, "risk_level": level}
