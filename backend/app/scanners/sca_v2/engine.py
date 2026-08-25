from __future__ import annotations
import json, math, re
from pathlib import Path
from typing import Any
from app.scanners.sca.scanner import SCAScanner
from app.scanners.sca_v2.intel import ThreatIntelProvider, priority_score
from app.scanners.sca_v2.models import LicenseAssessment, SCAIntelligenceResult

LICENSE_RISK = {
    "agpl": ("high", "Strong copyleft; review distribution/service obligations."),
    "gpl": ("medium", "Copyleft license; review linking/distribution obligations."),
    "lgpl": ("low", "Weak copyleft; confirm obligations for bundled/linked use."),
    "apache-2.0": ("low", "Permissive license; review NOTICE/patent terms."),
    "mit": ("low", "Permissive license; preserve copyright/license notice."),
    "bsd": ("low", "Permissive license; preserve notices."),
}

class SCAIntelligenceEngine:
    def __init__(self) -> None:
        self.provider = ThreatIntelProvider()
        self.base = SCAScanner()

    def analyze(self, path: str, profile: str = "standard", policy: dict[str, Any] | None = None) -> SCAIntelligenceResult:
        result = self.base.scan_path(path, profile)
        deps = [d.as_dict() for d in result.dependencies]
        root = Path(path).expanduser().resolve()
        intel = []
        licenses = []
        findings = []
        supply = self._supply_chain_indicators(root, deps)
        for dep in deps:
            for record in self.provider.lookup(dep["name"], dep["ecosystem"], dep.get("version", "unknown")):
                score = priority_score(record.severity, record.cvss, record.epss, record.kev, dep.get("reachable"))
                row = record.as_dict() | {"priority_score": score, "package_version": dep.get("version"), "reachable": dep.get("reachable"), "direct": dep.get("direct", True)}
                intel.append(row)
                finding_sev = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
                findings.append({
                    "finding_key": f"SCA2-{record.advisory_id}-{dep['name']}",
                    "title": f"{record.package}@{dep.get('version')} affected by {record.advisory_id}",
                    "severity": finding_sev,
                    "confidence": "high" if dep.get("reachable") is True else "medium",
                    "category": "Software Supply Chain",
                    "endpoint": dep.get("manifest", ""),
                    "description": f"Threat intelligence enrichment from {record.source}; priority score {score}/100.",
                    "evidence": row,
                    "remediation": f"Upgrade {record.package} to {record.fixed_versions[0]} or later." if record.fixed_versions else f"Review vendor advisory {record.advisory_id}.",
                })
            assessment = self._license(dep.get("license"))
            licenses.append(LicenseAssessment(dep["name"], dep["ecosystem"], dep.get("license"), assessment[0], assessment[1]).__dict__)
        findings.extend(supply)
        gate = self._evaluate_policy(findings, policy or {})
        findings.extend(gate[1])
        return SCAIntelligenceResult(dependencies=deps, graph=self._graph(deps), intelligence=intel, license_assessments=licenses, supply_chain_indicators=supply, policy=gate[0], sbom_diff={}, findings=findings)

    def _license(self, value: str | None) -> tuple[str, str]:
        if not value: return ("unknown", "No declared license metadata available.")
        v=value.lower().replace(" ", "")
        for needle, result in LICENSE_RISK.items():
            if needle in v: return result
        return ("review", "License identifier is not in the built-in classification catalog.")

    def _graph(self, deps: list[dict[str, Any]]) -> dict[str, Any]:
        nodes=[{"id":f"{d['ecosystem']}:{d['name']}@{d['version']}","type":"dependency","direct":d.get("direct",True)} for d in deps]
        return {"nodes":nodes,"edges":[],"edge_reason":"Lockfile/transitive graph enrichment can populate package relationships when available."}

    def _supply_chain_indicators(self, root: Path, deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
        findings=[]
        declared_names={d["name"].lower() for d in deps}
        if root.is_dir():
            for p in [root/"package.json", root/"package-lock.json", root/"requirements.txt", root/"pyproject.toml"]:
                if p.exists() and p.stat().st_size > 2_000_000:
                    findings.append({"finding_key":"SCA2-SUPPLY-LARGE-MANIFEST","title":"Unusually large dependency manifest","severity":"low","confidence":"medium","category":"Supply Chain","endpoint":str(p),"description":"Large manifest can complicate review and indicate generated or bundled dependency metadata.","evidence":{"size_bytes":p.stat().st_size},"remediation":"Review and pin dependencies using lockfiles."})
        for name in declared_names:
            normalized=re.sub(r"[^a-z0-9]", "", name)
            if len(normalized) >= 8 and any(normalized == x or (len(normalized)-len(x) <= 1 and normalized[:5] == x[:5]) for x in {"request", "lodash", "express"}):
                continue
        return findings

    def _evaluate_policy(self, findings: list[dict[str, Any]], policy: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        limits=policy.get("max_severity_counts", {}) if isinstance(policy, dict) else {}
        counts={k:sum(1 for f in findings if f.get("severity")==k) for k in ("critical","high","medium","low")}
        violations=[]
        for sev, max_count in limits.items():
            try:
                if counts.get(sev,0) > int(max_count):
                    violations.append({"finding_key":f"SCA2-POLICY-{sev}","title":f"SCA policy gate exceeded for {sev}","severity":"high" if sev in ("critical","high") else "medium","confidence":"confirmed","category":"Policy","description":f"{counts.get(sev,0)} {sev} findings exceed configured maximum {max_count}.","evidence":{"count":counts.get(sev,0),"maximum":int(max_count)},"remediation":"Upgrade, remove, or explicitly approve affected dependencies."})
            except (ValueError, TypeError):
                continue
        policy_result={"passed":not violations,"counts":counts,"limits":limits,"violations":len(violations)}
        return policy_result, violations

    @staticmethod
    def sbom_diff(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
        old_map={(str(c.get("purl")),str(c.get("version"))):c for c in old.get("components",[])}
        new_map={(str(c.get("purl")),str(c.get("version"))):c for c in new.get("components",[])}
        added=[v for k,v in new_map.items() if k not in old_map]
        removed=[v for k,v in old_map.items() if k not in new_map]
        old_by_purl={str(c.get("purl")):c for c in old.get("components",[])}
        new_by_purl={str(c.get("purl")):c for c in new.get("components",[])}
        changed=[{"purl":p,"from":o.get("version"),"to":new_by_purl[p].get("version")} for p,o in old_by_purl.items() if p in new_by_purl and o.get("version") != new_by_purl[p].get("version")]
        return {"added":added,"removed":removed,"changed":changed}
