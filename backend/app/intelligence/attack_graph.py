from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

SEVERITY_SCORE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
ENTRY_KEYS = {"WEB-CSP-001", "WEB-HDR-001", "API-DISCOVERY", "API-SPEC-AUTH-SCHEME", "AI-PI-01", "RAG-INDIRECT-01"}
AUTH_WORDS = ("authentication", "login", "jwt", "oauth", "oidc", "session", "identity")
ACCESS_WORDS = ("access control", "authorization", "bola", "bfla", "privilege")
DATA_WORDS = ("sensitive", "secret", "credential", "pii", "data disclosure", "information disclosure")
REMOTE_WORDS = ("ssrf", "server-side request", "remote", "external request")
INJECTION_WORDS = ("injection", "xss", "sqli", "command", "template")


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str
    label: str
    severity: str = "info"
    finding_id: int | None = None


def _text(f: dict[str, Any]) -> str:
    return " ".join(str(f.get(k, "")) for k in ("title", "finding_key", "category", "description")).lower()


def _host(endpoint: str | None) -> str:
    if not endpoint:
        return "unknown"
    parsed = urlparse(endpoint)
    return parsed.netloc or parsed.path.split("/", 1)[0] or "unknown"


def _severity(f: dict[str, Any]) -> int:
    return SEVERITY_SCORE.get(str(f.get("severity", "info")).lower(), 1)


def build_attack_graph(findings: Iterable[Any]) -> dict[str, Any]:
    raw = []
    for item in findings:
        if isinstance(item, dict):
            raw.append(dict(item))
        else:
            raw.append({k: getattr(item, k, None) for k in ("id", "finding_key", "title", "severity", "category", "endpoint", "description", "confidence", "remediation", "evidence")})

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    paths: list[dict[str, Any]] = []

    for f in raw:
        fid = str(f.get("id") or f.get("finding_key") or len(nodes))
        host = _host(f.get("endpoint"))
        nodes.append(GraphNode(f"finding:{fid}", "finding", str(f.get("title", "Finding")), str(f.get("severity", "info")), f.get("id")).__dict__)
        host_node = f"asset:{host}"
        nodes.append(GraphNode(host_node, "asset", host).__dict__)
        edges.append({"source": host_node, "target": f"finding:{fid}", "relation": "contains"})

    # Uniquify nodes while preserving order.
    seen = set(); nodes = [n for n in nodes if not (n["id"] in seen or seen.add(n["id"]))]

    grouped: dict[str, list[dict[str, Any]]] = {}
    for f in raw:
        grouped.setdefault(_host(f.get("endpoint")), []).append(f)

    for host, fs in grouped.items():
        candidates = [f for f in fs if _severity(f) >= 3]
        # Candidate chains are intentionally conservative: they represent relationships to validate,
        # not proof of exploitability.
        for auth in candidates:
            ta = _text(auth)
            if not any(w in ta for w in AUTH_WORDS):
                continue
            for access in candidates:
                if access is auth:
                    continue
                tb = _text(access)
                if any(w in tb for w in ACCESS_WORDS):
                    a, b = str(auth.get("id") or auth.get("finding_key")), str(access.get("id") or access.get("finding_key"))
                    edges.append({"source": f"finding:{a}", "target": f"finding:{b}", "relation": "may-enable", "confidence": "candidate"})
                    paths.append({"asset": host, "risk": "critical" if max(_severity(auth), _severity(access)) >= 5 else "high", "nodes": [a, b], "reason": "Authentication and authorization weaknesses on the same asset may combine into a privilege-escalation path; application-side validation is required."})

        for injection in candidates:
            ti = _text(injection)
            if not any(w in ti for w in INJECTION_WORDS + REMOTE_WORDS):
                continue
            for data in candidates:
                if data is injection:
                    continue
                td = _text(data)
                if any(w in td for w in DATA_WORDS):
                    a, b = str(injection.get("id") or injection.get("finding_key")), str(data.get("id") or data.get("finding_key"))
                    edges.append({"source": f"finding:{a}", "target": f"finding:{b}", "relation": "may-reach", "confidence": "candidate"})
                    paths.append({"asset": host, "risk": "high", "nodes": [a, b], "reason": "An injection/request-boundary weakness coexists with sensitive-data exposure indicators; validate actual reachability and impact."})

        if len(candidates) >= 3:
            ranked = sorted(candidates, key=_severity, reverse=True)[:3]
            ids = [str(x.get("id") or x.get("finding_key")) for x in ranked]
            risk = "critical" if max(_severity(x) for x in ranked) >= 5 else "high"
            paths.append({"asset": host, "risk": risk, "nodes": ids, "reason": "Three or more material weaknesses share an attack surface; the combination should be reviewed as a potential attack path."})

    # De-duplicate paths and edges.
    edge_seen = set(); clean_edges = []
    for e in edges:
        key = (e["source"], e["target"], e["relation"])
        if key not in edge_seen:
            edge_seen.add(key); clean_edges.append(e)
    path_seen = set(); clean_paths = []
    for p in paths:
        key = (p["asset"], tuple(p["nodes"]))
        if key not in path_seen:
            path_seen.add(key); clean_paths.append(p)

    return {"nodes": nodes, "edges": clean_edges, "paths": clean_paths, "path_count": len(clean_paths), "node_count": len(nodes), "edge_count": len(clean_edges)}
