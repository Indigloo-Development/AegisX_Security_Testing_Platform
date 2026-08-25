from __future__ import annotations
from collections import Counter
from typing import Any
from .rules import RULES

def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity = Counter(str(f.get("severity", "info")).lower() for f in findings)
    categories = Counter(str(f.get("category", "Unknown")) for f in findings)
    owasp = Counter(tag for f in findings for tag in f.get("owasp", []))
    cwe = Counter(tag for f in findings for tag in f.get("cwe", []))
    return {
        "total": len(findings),
        "severity": dict(severity),
        "categories": dict(categories),
        "owasp": dict(owasp),
        "cwe": dict(cwe),
    }

def rule_catalog() -> list[dict[str, Any]]:
    return [{
        "key": r.key, "title": r.title, "category": r.category,
        "severity": r.severity, "owasp": list(r.owasp), "cwe": list(r.cwe),
        "confidence": r.confidence, "tags": list(r.tags),
    } for r in RULES]
