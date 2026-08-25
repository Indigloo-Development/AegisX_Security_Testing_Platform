from __future__ import annotations
import math
from typing import Iterable
from .models import ThreatIntelRecord

# Offline deterministic enrichment catalog used for tests/demo. Production adapters
# can map OSV/NVD/vendor/KEV feeds into the same record model without changing the API.
CATALOG = [
    ThreatIntelRecord("OSV-AX-NPM-001", "lodash", "npm", "high", cvss=7.4, epss=0.82, kev=True, cwe=["CWE-1321"], fixed_versions=["4.17.21"], source="offline-demo"),
    ThreatIntelRecord("OSV-AX-PY-001", "requests", "PyPI", "medium", cvss=5.3, epss=0.12, kev=False, fixed_versions=["2.32.0"], source="offline-demo"),
    ThreatIntelRecord("OSV-AX-JAVA-001", "org.springframework:spring-core", "Maven", "high", cvss=8.1, epss=0.38, kev=False, cwe=["CWE-400"], fixed_versions=["6.1.8"], source="offline-demo"),
]

class ThreatIntelProvider:
    def lookup(self, package: str, ecosystem: str, version: str) -> list[ThreatIntelRecord]:
        from app.scanners.sca.advisories import affects, ADVISORIES
        matches: list[ThreatIntelRecord] = []
        for record in CATALOG:
            if record.package.lower() == package.lower() and record.ecosystem.lower() == ecosystem.lower():
                if version not in ("", "unknown"):
                    matches.append(record)
        # Backfill the original deterministic advisory catalog when a package matches.
        for adv in ADVISORIES:
            if adv.package.lower() == package.lower() and adv.ecosystem.lower() == ecosystem.lower() and affects(adv, version):
                if not any(x.advisory_id == adv.advisory_id for x in matches):
                    matches.append(ThreatIntelRecord(
                        advisory_id=adv.advisory_id,
                        package=adv.package,
                        ecosystem=adv.ecosystem,
                        severity=adv.severity,
                        cwe=adv.cwe,
                        fixed_versions=adv.fixed_versions,
                        references=adv.references,
                        source="legacy-offline-catalog",
                    ))
        return matches

    def import_records(self, records: Iterable[dict]) -> int:
        added = 0
        existing = {(r.advisory_id, r.package.lower(), r.ecosystem.lower()) for r in CATALOG}
        for row in records:
            try:
                rec = ThreatIntelRecord(
                    advisory_id=str(row["advisory_id"]), package=str(row["package"]), ecosystem=str(row["ecosystem"]),
                    severity=str(row.get("severity", "unknown")), cvss=float(row["cvss"]) if row.get("cvss") is not None else None,
                    epss=float(row["epss"]) if row.get("epss") is not None else None, kev=bool(row.get("kev", False)),
                    cwe=list(row.get("cwe", [])), fixed_versions=list(row.get("fixed_versions", [])),
                    references=list(row.get("references", [])), source=str(row.get("source", "imported")),
                    published=row.get("published"), modified=row.get("modified"),
                )
                key=(rec.advisory_id, rec.package.lower(), rec.ecosystem.lower())
                if key not in existing:
                    CATALOG.append(rec); existing.add(key); added += 1
            except (KeyError, TypeError, ValueError):
                continue
        return added

def priority_score(severity: str, cvss: float | None, epss: float | None, kev: bool, reachable: bool | None) -> int:
    score = {"critical": 75, "high": 60, "medium": 40, "low": 20, "unknown": 10}.get(severity.lower(), 10)
    if cvss is not None:
        score += int(min(max(cvss, 0), 10) * 1.5)
    if epss is not None:
        score += int(min(max(epss, 0), 1) * 12)
    if kev:
        score += 10
    if reachable is True:
        score += 10
    elif reachable is False:
        score -= 10
    return max(0, min(score, 100))
