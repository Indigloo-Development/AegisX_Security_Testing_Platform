from app.alerting_v29 import AlertEvent, AlertDeduplicator, build_monitoring_alerts, build_scan_alert, threshold_match


def test_threshold():
    assert threshold_match("critical", "high")
    assert threshold_match("high", "medium")
    assert not threshold_match("low", "high")


def test_alert_building_and_threshold():
    diff = {"state":"changed", "endpoint_drift":{"added":["/admin"],"removed":[]}, "technology_drift":{"added":[],"removed":[]}, "dependency_drift":{"added":["pkg@1.2"],"removed":[]}}
    events = build_monitoring_alerts(diff, "a1", "medium")
    assert [e.alert_type for e in events] == ["endpoint_drift", "dependency_drift"]


def test_dedup():
    d = AlertDeduplicator(); e = AlertEvent("x", "high", "subject", asset_id="a1", message="m")
    assert d.accept(e) is True
    assert d.accept(e) is False


def test_scan_failure():
    assert build_scan_alert("scan1", "completed") is None
    event = build_scan_alert("scan1", "failed", asset_id="a1", error="timeout")
    assert event is not None and event.alert_type == "scan_failure" and event.severity == "high"
