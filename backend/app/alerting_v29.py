from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

@dataclass
class AlertEvent:
    alert_type: str
    severity: str
    subject: str
    asset_id: str | None = None
    finding_key: str | None = None
    message: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def fingerprint(self) -> str:
        raw = json.dumps({
            "alert_type": self.alert_type,
            "severity": self.severity,
            "subject": self.subject,
            "asset_id": self.asset_id,
            "finding_key": self.finding_key,
            "message": self.message,
        }, sort_keys=True, separators=(",", ":"))
        return sha256(raw.encode()).hexdigest()


def threshold_match(severity: str, minimum: str = "medium") -> bool:
    return SEVERITY_RANK.get(severity.lower(), 0) >= SEVERITY_RANK.get(minimum.lower(), 0)


class AlertDeduplicator:
    def __init__(self) -> None:
        self._seen: dict[str, str] = {}

    def accept(self, event: AlertEvent) -> bool:
        if event.fingerprint in self._seen:
            return False
        self._seen[event.fingerprint] = event.created_at
        return True

    def clear(self) -> None:
        self._seen.clear()


class NotificationAdapter:
    name = "base"
    def send(self, event: AlertEvent) -> dict[str, Any]:
        raise NotImplementedError


class WebhookAdapter(NotificationAdapter):
    name = "webhook"
    def send(self, event: AlertEvent) -> dict[str, Any]:
        return {"adapter": self.name, "delivered": False, "mode": "dry_run", "fingerprint": event.fingerprint}


class EmailAdapter(NotificationAdapter):
    name = "email"
    def send(self, event: AlertEvent) -> dict[str, Any]:
        return {"adapter": self.name, "delivered": False, "mode": "dry_run", "fingerprint": event.fingerprint}


class SlackAdapter(NotificationAdapter):
    name = "slack"
    def send(self, event: AlertEvent) -> dict[str, Any]:
        return {"adapter": self.name, "delivered": False, "mode": "dry_run", "fingerprint": event.fingerprint}


def build_monitoring_alerts(diff: dict[str, Any], asset_id: str, minimum: str = "medium") -> list[AlertEvent]:
    candidates: list[AlertEvent] = []
    if diff.get("state") == "new":
        candidates.append(AlertEvent("new_asset", "high", "New asset detected", asset_id, asset_id, "A new monitored asset was observed."))
    endpoint = diff.get("endpoint_drift", {})
    if endpoint.get("added") or endpoint.get("removed"):
        candidates.append(AlertEvent("endpoint_drift", "medium", "Endpoint drift detected", asset_id, asset_id, "Endpoint inventory changed.", {"added": endpoint.get("added", []), "removed": endpoint.get("removed", [])}))
    tech = diff.get("technology_drift", {})
    if tech.get("added") or tech.get("removed"):
        candidates.append(AlertEvent("technology_drift", "medium", "Technology drift detected", asset_id, asset_id, "Technology inventory changed.", {"added": tech.get("added", []), "removed": tech.get("removed", [])}))
    deps = diff.get("dependency_drift", {})
    if deps.get("added") or deps.get("removed"):
        candidates.append(AlertEvent("dependency_drift", "high", "Dependency drift detected", asset_id, asset_id, "Dependency inventory changed.", {"added": deps.get("added", []), "removed": deps.get("removed", [])}))
    return [x for x in candidates if threshold_match(x.severity, minimum)]


def build_scan_alert(scan_id: str, status: str, *, asset_id: str | None = None, error: str | None = None) -> AlertEvent | None:
    if status.lower() not in {"failed", "cancelled"}:
        return None
    return AlertEvent("scan_failure", "high", "Scan execution failed", asset_id, scan_id, error or f"scan status: {status}")
