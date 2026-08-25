from __future__ import annotations
import re
from pathlib import Path
from difflib import SequenceMatcher
from typing import Any
from app.scanners.sca.scanner import SCAScanner
from app.scanners.sca_v2.intel import ThreatIntelProvider, priority_score
from .graph import parse_package_lock, parse_cargo_lock
from .models import ReachabilityEvidence, SupplyChainAssessment, SCAReachabilityResult

COMMON_REGISTRY_NAMES = {
    "npm": {"lodash", "express", "react", "axios", "request"},
    "PyPI": {"requests", "flask", "django", "numpy", "pandas"},
    "Maven": {"org.springframework:spring-core", "org.apache.logging.log4j:log4j-core"},
}

class SCAReachabilityEngine:
    def __init__(self) -> None:
        self.base = SCAScanner()
        self.provider = ThreatIntelProvider()

    def analyze(self, path: str, profile: str = "deep", include_dev: bool = False) -> SCAReachabilityResult:
        root=Path(path).expanduser().resolve()
        if not root.exists():
            raise ValueError("SCA source path does not exist")
        base=self.base.scan_path(str(root), profile)
        base_deps=[d.as_dict() for d in base.dependencies if include_dev or d.scope != "development"]
        lock_deps, lock_edges=self._parse_lockfiles(root)
        merged=self._merge_dependencies(base_deps, lock_deps)
        graph=self._build_graph(merged, lock_edges)
        reachability=self._reachability(root, merged, graph)
        supply=self._supply_chain(root, merged)
        intelligence=[]; findings=[]
        reach_map={(r["ecosystem"],r["package"]):r for r in reachability}
        for dep in merged:
            reach=reach_map.get((dep["ecosystem"],dep["name"]))
            if reach:
                dep["reachability_status"]=reach["status"]
                dep["reachability_confidence"]=reach["confidence"]
                dep["reachability_evidence"]=reach["evidence"]
            for record in self.provider.lookup(dep["name"], dep["ecosystem"], dep.get("version","unknown")):
                reachable_value = True if reach and reach["status"] in {"direct", "reachable"} else False if reach and reach["status"] == "unreachable" else None
                score=priority_score(record.severity, record.cvss, record.epss, record.kev, reachable_value)
                row=record.as_dict() | {"package_version":dep.get("version"),"direct":dep.get("direct",False),"reachable":reachable_value,"reachability_confidence":reach.get("confidence") if reach else "low","priority_score":score}
                intelligence.append(row)
                sev="critical" if score>=85 else "high" if score>=65 else "medium" if score>=40 else "low"
                confidence="high" if reach and reach["confidence"] in {"high","medium"} else "medium"
                findings.append({"finding_key":f"SCA3-{record.advisory_id}-{dep['name']}","title":f"{dep['name']}@{dep.get('version')} affected by {record.advisory_id}","severity":sev,"confidence":confidence,"category":"Software Supply Chain","endpoint":dep.get("manifest",""),"description":f"Advisory matched with reachability status {reach.get('status') if reach else 'unknown'}.","evidence":row,"remediation":f"Upgrade to {record.fixed_versions[0]}." if record.fixed_versions else "Review the advisory and update the dependency."})
        for assessment in supply:
            if assessment["risk"] in {"high","critical"}:
                findings.append({"finding_key":f"SCA3-SUPPLY-{assessment['package']}","title":f"Supply-chain risk indicators for {assessment['package']}","severity":assessment["risk"],"confidence":"medium","category":"Software Supply Chain","endpoint":"","description":"Supply-chain indicators require review; this is not proof of maliciousness.","evidence":assessment,"remediation":"Validate package provenance, registry, lockfile integrity, ownership and package history."})
        summary={
            "dependencies":len(merged),
            "direct":sum(1 for d in merged if d.get("direct")),
            "transitive":sum(1 for d in merged if not d.get("direct")),
            "reachable":sum(1 for r in reachability if r["status"] in {"direct","reachable"}),
            "unreachable":sum(1 for r in reachability if r["status"]=="unreachable"),
            "unknown":sum(1 for r in reachability if r["status"]=="unknown"),
            "high_supply_chain":sum(1 for s in supply if s["risk"] in {"high","critical"}),
            "findings":len(findings),
        }
        return SCAReachabilityResult(merged,graph,reachability,supply,intelligence,findings,summary)

    def _parse_lockfiles(self, root: Path) -> tuple[list[dict[str,Any]], list[dict[str,Any]]]:
        deps=[]; edges=[]
        if root.is_dir():
            for p in root.rglob("package-lock.json"):
                d,e=parse_package_lock(p); deps.extend(d); edges.extend(e)
            for p in root.rglob("Cargo.lock"):
                d,e=parse_cargo_lock(p); deps.extend(d); edges.extend(e)
        return deps,edges

    @staticmethod
    def _merge_dependencies(base: list[dict[str,Any]], lock: list[dict[str,Any]]) -> list[dict[str,Any]]:
        out={ (d.get("ecosystem"),d.get("name")):dict(d) for d in base }
        for row in lock:
            key=(row.get("ecosystem"),row.get("name")); current=out.get(key)
            if current:
                current["version"]=row.get("version",current.get("version")); current["source"]=row.get("source",current.get("source","")); current["lockfile_present"]=True
                if row.get("direct"): current["direct"]=True
            else:
                out[key]=dict(row)
        return list(out.values())

    @staticmethod
    def _build_graph(deps: list[dict[str,Any]], edges: list[dict[str,Any]]) -> dict[str,Any]:
        nodes=[]; ids=set()
        for d in deps:
            nid=f"{d['ecosystem']}:{d['name']}@{d.get('version','unknown')}"
            if nid not in ids:
                nodes.append({"id":nid,"type":"dependency","name":d["name"],"ecosystem":d["ecosystem"],"version":d.get("version"),"direct":d.get("direct",False)}); ids.add(nid)
        root_edges=[]
        known={n["name"] for n in nodes}
        for e in edges:
            if e.get("target") and any(n["name"] in str(e["target"]) for n in nodes): root_edges.append(e)
        return {"nodes":nodes,"edges":root_edges,"root":"npm:root@0" if any(d["ecosystem"]=="npm" for d in deps) else None}

    def _reachability(self, root: Path, deps: list[dict[str,Any]], graph: dict[str,Any]) -> list[dict[str,Any]]:
        source=self._source_text(root)
        out=[]
        for d in deps:
            if d.get("direct"):
                evidence=[f"Declared direct dependency in {d.get('manifest','unknown manifest')}" ]
                status="direct"; confidence="high"
            else:
                marker=d["name"].split("/")[-1].split(":")[-1].replace("-","_")
                hits=[]
                if marker and marker.lower() in source.lower(): hits.append(f"Package marker '{marker}' referenced in source")
                status="reachable" if hits else "unknown"; confidence="medium" if hits else "low"; evidence=hits or ["No deterministic usage evidence found; runtime reachability not proven."]
            out.append(ReachabilityEvidence(d["name"],d["ecosystem"],status,evidence,confidence).as_dict())
        return out

    @staticmethod
    def _source_text(root: Path) -> str:
        if not root.is_dir(): return ""
        chunks=[]
        patterns=("*.py","*.js","*.jsx","*.ts","*.tsx","*.java","*.go","*.rs","*.php","*.cs")
        files=[]
        for pat in patterns:
            files.extend(list(root.rglob(pat))[:120])
        for p in files[:600]:
            try: chunks.append(p.read_text(encoding="utf-8",errors="ignore")[:160000])
            except OSError: pass
        return "\n".join(chunks)

    def _supply_chain(self, root: Path, deps: list[dict[str,Any]]) -> list[dict[str,Any]]:
        out=[]
        for d in deps:
            indicators=[]
            name=d["name"].lower()
            normalized=re.sub(r"[^a-z0-9]", "", name)
            common=COMMON_REGISTRY_NAMES.get(d["ecosystem"],set())
            for canonical in common:
                cn=re.sub(r"[^a-z0-9]", "", canonical.lower())
                ratio=SequenceMatcher(None,normalized,cn).ratio()
                if 0.78 <= ratio < 1 and len(cn)>=6:
                    indicators.append({"type":"typosquatting-similarity","reference":canonical,"similarity":round(ratio,3)})
            if d.get("source") in {"package-lock-legacy","Cargo.lock"} and not d.get("lockfile_present",True):
                indicators.append({"type":"provenance","message":"Dependency discovered from lock metadata without a root manifest match."})
            if not d.get("version") or d.get("version")=="unknown":
                indicators.append({"type":"unpinned-version","message":"Exact dependency version is not known."})
            risk="high" if any(x["type"]=="typosquatting-similarity" for x in indicators) else "medium" if indicators else "info"
            out.append(SupplyChainAssessment(d["name"],d["ecosystem"],indicators,risk).as_dict())
        return out
