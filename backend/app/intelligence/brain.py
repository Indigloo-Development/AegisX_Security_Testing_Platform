from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable


SEVERITY_WEIGHT = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass(frozen=True)
class FindingView:
    id: int | None
    finding_key: str
    title: str
    severity: str
    confidence: str
    category: str
    endpoint: str | None
    description: str
    evidence: dict[str, Any]
    remediation: str | None

    @classmethod
    def from_obj(cls, obj: Any) -> "FindingView":
        if isinstance(obj, dict):
            return cls(
                id=obj.get("id"), finding_key=str(obj.get("finding_key", "GENERIC")),
                title=str(obj.get("title", "Security finding")), severity=str(obj.get("severity", "info")).lower(),
                confidence=str(obj.get("confidence", "potential")).lower(), category=str(obj.get("category", "Unknown")),
                endpoint=obj.get("endpoint"), description=str(obj.get("description", "")),
                evidence=obj.get("evidence") or {}, remediation=obj.get("remediation"),
            )
        return cls(
            id=getattr(obj, "id", None), finding_key=str(getattr(obj, "finding_key", "GENERIC")),
            title=str(getattr(obj, "title", "Security finding")), severity=getattr(getattr(obj, "severity", None), "value", "info"),
            confidence=str(getattr(obj, "confidence", "potential")).lower(), category=str(getattr(obj, "category", "Unknown")),
            endpoint=getattr(obj, "endpoint", None), description=str(getattr(obj, "description", "")),
            evidence=getattr(obj, "evidence", None) or {}, remediation=getattr(obj, "remediation", None),
        )


def _norm(text: str | None) -> str:
    return " ".join((text or "").lower().split())


def finding_fingerprint(f: FindingView) -> str:
    stable = "|".join([
        _norm(f.finding_key), _norm(f.title), _norm(f.category), _norm(f.endpoint),
    ])
    return sha256(stable.encode()).hexdigest()[:16]


def deduplicate(findings: Iterable[Any]) -> list[dict[str, Any]]:
    chosen: dict[str, FindingView] = {}
    for raw in findings:
        f = FindingView.from_obj(raw)
        fp = finding_fingerprint(f)
        current = chosen.get(fp)
        if current is None or SEVERITY_WEIGHT.get(f.severity, 1) > SEVERITY_WEIGHT.get(current.severity, 1):
            chosen[fp] = f
    return [
        {"fingerprint": fp, "finding_key": f.finding_key, "title": f.title, "severity": f.severity,
         "confidence": f.confidence, "category": f.category, "endpoint": f.endpoint, "description": f.description,
         "evidence": f.evidence, "remediation": f.remediation}
        for fp, f in chosen.items()
    ]


def correlate_attack_surfaces(findings: Iterable[Any]) -> list[dict[str, Any]]:
    items = [FindingView.from_obj(x) for x in findings]
    buckets: dict[str, list[FindingView]] = {}
    for f in items:
        endpoint = f.endpoint or "unknown-asset"
        host = endpoint.split("/", 3)[2] if "://" in endpoint and len(endpoint.split("/", 3)) > 2 else endpoint
        buckets.setdefault(host, []).append(f)

    chains: list[dict[str, Any]] = []
    for asset, fs in buckets.items():
        categories = {f.category.lower() for f in fs}
        keys = {f.finding_key for f in fs}
        severity = max((SEVERITY_WEIGHT.get(f.severity, 1) for f in fs), default=1)
        if len(fs) >= 2 and ("authentication" in " ".join(categories) or any("access" in _norm(f.title) for f in fs)):
            chains.append({
                "asset": asset,
                "risk": "critical" if severity >= 5 else "high" if severity >= 4 else "medium",
                "nodes": [f.finding_key for f in fs],
                "reason": "Multiple findings on the same attack surface may combine into an exploit chain; validate authorization and business impact.",
            })
        elif len(keys) >= 3:
            chains.append({
                "asset": asset,
                "risk": "high" if severity >= 4 else "medium",
                "nodes": list(keys),
                "reason": "Multiple independent weaknesses share an attack surface and merit correlated review.",
            })
    return chains


def build_scan_plan(target_type: str, profile: str = "standard", findings: Iterable[Any] = ()) -> dict[str, Any]:
    t = _norm(target_type)
    p = _norm(profile)
    scanners: list[str] = []
    rationale: list[str] = []
    if "web" in t or "url" in t or not t:
        scanners += ["web", "csp"]
        rationale.append("Web targets benefit from crawler/HTTP analysis and response-policy inspection.")
    if "api" in t or "rest" in t or "graphql" in t or "soap" in t or "grpc" in t:
        scanners.append("api")
        rationale.append("API targets require protocol and schema inventory before deeper security testing.")
    if "ai" in t or "llm" in t:
        scanners.append("ai")
        rationale.append("AI targets require bounded prompt and response security campaigns.")
    if "rag" in t:
        scanners += ["ai", "rag"]
        rationale.append("RAG targets require both model-layer and retrieval-layer analysis.")
    if "agent" in t or "mcp" in t:
        scanners += ["ai", "agent"]
        rationale.append("Agentic targets require tool/identity/agency analysis in addition to model testing.")
    if "source" in t or "repo" in t or "code" in t:
        scanners.append("sca")
        rationale.append("Source targets should be inventoried for dependencies and SBOM generation.")
    if p == "quick":
        scanners = scanners[:3]
    elif p in {"deep", "red-team", "red team"}:
        for x in ["api", "sca", "ai", "rag", "agent", "csp"]:
            if x not in scanners:
                scanners.append(x)
        rationale.append("Deep/red-team profiles expand coverage across adjacent attack surfaces.")
    # Stable order and uniqueness.
    scanners = list(dict.fromkeys(scanners))
    return {"profile": profile, "target_type": target_type, "recommended_scanners": scanners, "rationale": rationale}


def risk_assessment(findings: Iterable[Any]) -> dict[str, Any]:
    items = [FindingView.from_obj(x) for x in findings]
    if not items:
        return {"overall_risk": "info", "score": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "explanation": "No findings were supplied."}
    counts = {s: sum(1 for f in items if f.severity == s) for s in SEVERITY_WEIGHT}
    score = min(100, sum(SEVERITY_WEIGHT.get(f.severity, 1) * 8 for f in items) + counts["critical"] * 10)
    overall = "critical" if counts["critical"] else "high" if counts["high"] else "medium" if counts["medium"] else "low" if counts["low"] else "info"
    explanation = f"Risk is {overall} based on {len(items)} finding(s), with {counts['critical']} critical and {counts['high']} high severity finding(s)."
    return {"overall_risk": overall, "score": score, **counts, "explanation": explanation}


def analyze(findings: Iterable[Any], target_type: str = "web", profile: str = "standard") -> dict[str, Any]:
    deduped = deduplicate(findings)
    chains = correlate_attack_surfaces(deduped)
    risk = risk_assessment(deduped)
    plan = build_scan_plan(target_type, profile, deduped)
    return {
        "finding_count": len(deduped),
        "findings": deduped,
        "attack_surface_correlations": chains,
        "risk": risk,
        "scan_plan": plan,
        "reasoning_mode": "deterministic-evidence-first",
    }
