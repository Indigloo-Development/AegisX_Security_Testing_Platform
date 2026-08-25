from __future__ import annotations

import csv
import io
import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

COMPLIANCE_MAP = {
    "broken access control": ["OWASP A01:2025", "CIS 6", "ISO27001 A.5.15"],
    "security misconfiguration": ["OWASP A02:2025", "CIS 4"],
    "injection": ["OWASP A05:2025", "CIS 16"],
    "authentication": ["OWASP A07:2025", "ISO27001 A.8.5"],
    "authorization": ["OWASP A01:2025", "ISO27001 A.5.15"],
    "sensitive data": ["OWASP A04:2025", "ISO27001 A.8.11"],
    "supply chain": ["OWASP A03:2025", "CIS 16"],
    "llm": ["OWASP LLM Top 10", "NIST AI RMF"],
    "rag": ["OWASP LLM Top 10", "NIST AI RMF"],
    "agent": ["OWASP Agentic Applications Top 10", "NIST AI RMF"],
}


def _norm_finding(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    severity = str(out.get("severity", "info")).lower()
    out["severity"] = severity
    out["confidence"] = str(out.get("confidence", "potential"))
    out["title"] = str(out.get("title", "Untitled finding"))
    out["finding_key"] = str(out.get("finding_key", out.get("id", "finding")))
    out["category"] = str(out.get("category", "Uncategorized"))
    out["description"] = str(out.get("description", ""))
    out["remediation"] = out.get("remediation") or "Review the evidence and apply the recommended secure configuration or code change."
    out["evidence"] = out.get("evidence") if isinstance(out.get("evidence"), dict) else {}
    return out


def normalize_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [_norm_finding(f) for f in findings]


def summarize_findings(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = normalize_findings(findings)
    counts = Counter(r["severity"] for r in rows)
    cats = Counter(r["category"] for r in rows)
    return {
        "total": len(rows),
        "severity": {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "categories": dict(cats.most_common()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def compliance_crosswalk(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = normalize_findings(findings)
    result: list[dict[str, Any]] = []
    for row in rows:
        text = f"{row['title']} {row['category']} {row['description']}".lower()
        controls: set[str] = set()
        for key, mapped in COMPLIANCE_MAP.items():
            if key in text:
                controls.update(mapped)
        if not controls:
            controls.update(["OWASP review required"])
        result.append({"finding_key": row["finding_key"], "title": row["title"], "controls": sorted(controls)})
    return result


def evidence_timeline(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline = []
    for row in normalize_findings(findings):
        evidence = row["evidence"]
        timeline.append({
            "finding_key": row["finding_key"],
            "timestamp": evidence.get("timestamp") or evidence.get("observed_at"),
            "endpoint": row.get("endpoint"),
            "severity": row["severity"],
            "confidence": row["confidence"],
            "evidence": evidence,
        })
    timeline.sort(key=lambda x: str(x.get("timestamp") or ""))
    return timeline


def build_report(findings: Iterable[dict[str, Any]], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    rows = normalize_findings(findings)
    summary = summarize_findings(rows)
    priorities = sorted(rows, key=lambda r: (-SEVERITY_ORDER.get(r["severity"], 0), r["title"]))
    return {
        "report_version": "55.0",
        "generated_at": summary["generated_at"],
        "metadata": metadata or {},
        "summary": summary,
        "findings": rows,
        "compliance_crosswalk": compliance_crosswalk(rows),
        "evidence_timeline": evidence_timeline(rows),
        "remediation_priorities": [
            {"finding_key": r["finding_key"], "title": r["title"], "severity": r["severity"], "remediation": r["remediation"]}
            for r in priorities
        ],
    }


def to_json_report(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


def to_csv_report(findings: Iterable[dict[str, Any]]) -> str:
    rows = normalize_findings(findings)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=["finding_key", "title", "severity", "confidence", "category", "endpoint", "description", "remediation"], extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def to_sarif(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = normalize_findings(findings)
    results = []
    rules = {}
    for r in rows:
        rid = r["finding_key"]
        rules[rid] = {
            "id": rid,
            "name": r["title"],
            "shortDescription": {"text": r["title"]},
            "help": {"text": r["remediation"]},
            "properties": {"category": r["category"], "confidence": r["confidence"]},
        }
        level = "error" if r["severity"] in ("critical", "high") else "warning" if r["severity"] == "medium" else "note"
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": r["description"]},
            "properties": {"severity": r["severity"], "confidence": r["confidence"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": r.get("endpoint") or "target"}}}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AegisX", "version": "55.0", "rules": list(rules.values())}}, "results": results}],
    }


def to_html_report(report: dict[str, Any]) -> str:
    s = report["summary"]
    rows = "".join(
        f"<tr><td>{escape(r['finding_key'])}</td><td>{escape(r['title'])}</td><td>{escape(r['severity'])}</td>"
        f"<td>{escape(r['confidence'])}</td><td>{escape(r['category'])}</td><td>{escape(str(r.get('endpoint') or ''))}</td></tr>"
        for r in report["findings"]
    )
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>AegisX Security Report</title>
<style>body{{font-family:Arial,sans-serif;margin:32px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f3f4f6}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{padding:14px;border:1px solid #ddd;border-radius:8px;min-width:110px}}</style></head><body>
<h1>AegisX Security Report</h1><p>Generated: {escape(report['generated_at'])}</p><div class='cards'>
<div class='card'><b>Total</b><br>{s['total']}</div><div class='card'><b>Critical</b><br>{s['severity']['critical']}</div><div class='card'><b>High</b><br>{s['severity']['high']}</div><div class='card'><b>Medium</b><br>{s['severity']['medium']}</div></div>
<h2>Findings</h2><table><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Confidence</th><th>Category</th><th>Endpoint</th></tr></thead><tbody>{rows}</tbody></table></body></html>"""
