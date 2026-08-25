from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Principal:
    name: str
    role: str
    tenant: Optional[str] = None
    permissions: List[str] = field(default_factory=list)


@dataclass
class AccessObservation:
    principal: str
    role: str
    tenant: Optional[str]
    endpoint: str
    method: str
    object_id: Optional[str] = None
    status: Optional[int] = None
    content_length: Optional[int] = None
    authorization_marker: Optional[str] = None


@dataclass
class AuthzFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    evidence: Dict[str, Any]
    remediation: str


def build_matrix(principals: List[Principal], endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    matrix: List[Dict[str, Any]] = []
    for p in principals:
        for ep in endpoints:
            methods = ep.get("methods") or [ep.get("method", "GET")]
            matrix.append({
                "principal": p.name,
                "role": p.role,
                "tenant": p.tenant,
                "endpoint": ep.get("path", ""),
                "methods": [m.upper() for m in methods],
                "expected_access": ep.get("allowed_roles", []),
            })
    return {"principals": len(principals), "endpoints": len(endpoints), "matrix": matrix}


def compare_observations(observations: List[AccessObservation]) -> List[AuthzFinding]:
    findings: List[AuthzFinding] = []
    grouped: Dict[tuple, List[AccessObservation]] = {}
    for obs in observations:
        key = (obs.endpoint, obs.method.upper(), obs.object_id)
        grouped.setdefault(key, []).append(obs)

    for key, group in grouped.items():
        if len(group) < 2:
            continue
        authorized = [g for g in group if (g.authorization_marker or "").lower() in {"allow", "authorized", "admin"}]
        denied = [g for g in group if (g.authorization_marker or "").lower() in {"deny", "forbidden", "unauthorized"}]
        if authorized and denied:
            # observation only: different responses are expected in properly protected APIs
            lengths = {g.content_length for g in group if g.content_length is not None}
            if len(lengths) > 1 and any(g.status in {200, 206} for g in denied):
                findings.append(AuthzFinding(
                    rule_id="AUTHZ-DIFF-001",
                    title="Potential authorization differential",
                    severity="HIGH",
                    confidence="POTENTIAL",
                    category="authorization",
                    evidence={"endpoint": key[0], "method": key[1], "object_id": key[2], "observations": [g.__dict__ for g in group]},
                    remediation="Review object/function authorization decisions and enforce deny-by-default with server-side policy checks.",
                ))
        # Tenant isolation observation: a non-matching tenant receiving a successful response is noteworthy.
        tenants = {g.tenant for g in group if g.tenant}
        if len(tenants) > 1:
            success = [g for g in group if g.status in {200, 206}]
            if len(success) >= 2:
                findings.append(AuthzFinding(
                    rule_id="AUTHZ-TENANT-001",
                    title="Potential cross-tenant access",
                    severity="CRITICAL",
                    confidence="POTENTIAL",
                    category="tenant-isolation",
                    evidence={"endpoint": key[0], "method": key[1], "object_id": key[2], "tenants": sorted(tenants)},
                    remediation="Enforce tenant scoping at the authorization layer and validate object ownership on every request.",
                ))
    return findings


def analyze_workflow(states: List[Dict[str, Any]]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for idx in range(1, len(states)):
        prev, current = states[idx - 1], states[idx]
        if current.get("requires") and current.get("requires") not in prev.get("completed", []):
            findings.append({"rule_id": "BIZLOGIC-STATE-001", "severity": "HIGH", "confidence": "POTENTIAL", "message": f"State {current.get('name')} declares prerequisite {current.get('requires')} that is not observed as completed."})
    return {"states": len(states), "findings": findings}
