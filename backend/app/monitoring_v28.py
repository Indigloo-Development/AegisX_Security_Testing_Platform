from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
import json
from typing import Any

class AssetType(str, Enum):
    web = "web"
    api = "api"
    ai = "ai"
    repository = "repository"
    domain = "domain"

class AlertType(str, Enum):
    new_asset = "new_asset"
    asset_drift = "asset_drift"
    endpoint_drift = "endpoint_drift"
    technology_drift = "technology_drift"
    dependency_drift = "dependency_drift"
    shadow_asset = "shadow_asset"
    scan_failure = "scan_failure"

@dataclass
class AssetSnapshot:
    asset_id: str
    asset_type: str
    target: str
    endpoints: list[str]
    technologies: list[str]
    dependencies: list[str]
    metadata: dict[str, Any]
    observed_at: str

    @property
    def fingerprint(self) -> str:
        raw = json.dumps({
            "asset_type": self.asset_type,
            "target": self.target,
            "endpoints": sorted(set(self.endpoints)),
            "technologies": sorted(set(self.technologies)),
            "dependencies": sorted(set(self.dependencies)),
            "metadata": self.metadata,
        }, sort_keys=True, separators=(",", ":"), default=str)
        return sha256(raw.encode()).hexdigest()


def normalize_snapshot(payload: dict[str, Any]) -> AssetSnapshot:
    now = datetime.now(timezone.utc).isoformat()
    return AssetSnapshot(
        asset_id=str(payload.get("asset_id") or payload.get("target") or sha256(str(payload).encode()).hexdigest()[:16]),
        asset_type=str(payload.get("asset_type") or AssetType.web.value),
        target=str(payload.get("target") or ""),
        endpoints=[str(x) for x in payload.get("endpoints", [])],
        technologies=[str(x) for x in payload.get("technologies", [])],
        dependencies=[str(x) for x in payload.get("dependencies", [])],
        metadata=dict(payload.get("metadata", {})),
        observed_at=str(payload.get("observed_at") or now),
    )


def _diff(old: list[str], new: list[str]) -> dict[str, list[str]]:
    a, b = set(old), set(new)
    return {"added": sorted(b - a), "removed": sorted(a - b), "unchanged": sorted(a & b)}


def compare_snapshots(previous: AssetSnapshot | None, current: AssetSnapshot) -> dict[str, Any]:
    if previous is None:
        return {
            "state": "new",
            "changed": True,
            "asset": {"added": [current.asset_id], "removed": [], "unchanged": []},
            "endpoint_drift": _diff([], current.endpoints),
            "technology_drift": _diff([], current.technologies),
            "dependency_drift": _diff([], current.dependencies),
        }
    endpoint = _diff(previous.endpoints, current.endpoints)
    tech = _diff(previous.technologies, current.technologies)
    deps = _diff(previous.dependencies, current.dependencies)
    metadata_changed = previous.metadata != current.metadata
    changed = any((endpoint["added"], endpoint["removed"], tech["added"], tech["removed"], deps["added"], deps["removed"])) or metadata_changed
    return {
        "state": "changed" if changed else "unchanged",
        "changed": changed,
        "metadata_changed": metadata_changed,
        "endpoint_drift": endpoint,
        "technology_drift": tech,
        "dependency_drift": deps,
        "previous_fingerprint": previous.fingerprint,
        "current_fingerprint": current.fingerprint,
    }


def detect_shadow_assets(known_targets: list[str], observed_targets: list[str]) -> list[str]:
    known = {x.lower().rstrip("/") for x in known_targets}
    return sorted({x.rstrip("/") for x in observed_targets if x.lower().rstrip("/") not in known})


def build_alerts(diff: dict[str, Any], *, asset_id: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    if diff.get("state") == "new":
        alerts.append({"type": AlertType.new_asset.value, "asset_id": asset_id, "severity": "high"})
    if diff.get("endpoint_drift", {}).get("added") or diff.get("endpoint_drift", {}).get("removed"):
        alerts.append({"type": AlertType.endpoint_drift.value, "asset_id": asset_id, "severity": "medium"})
    if diff.get("technology_drift", {}).get("added") or diff.get("technology_drift", {}).get("removed"):
        alerts.append({"type": AlertType.technology_drift.value, "asset_id": asset_id, "severity": "medium"})
    if diff.get("dependency_drift", {}).get("added") or diff.get("dependency_drift", {}).get("removed"):
        alerts.append({"type": AlertType.dependency_drift.value, "asset_id": asset_id, "severity": "medium"})
    return alerts
