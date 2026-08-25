from app.monitoring_v28 import normalize_snapshot, compare_snapshots, detect_shadow_assets, build_alerts

def snap(**kw):
    base={"asset_id":"a1","asset_type":"web","target":"https://example.com","endpoints":["/","/api"],"technologies":["nginx","react"],"dependencies":["lodash@4.17.21"],"metadata":{"env":"prod"}}
    base.update(kw); return normalize_snapshot(base)

def test_new_snapshot_and_fingerprint():
    cur=snap(); diff=compare_snapshots(None,cur)
    assert diff["state"]=="new" and diff["endpoint_drift"]["added"]==["/","/api"]

def test_drift_detected():
    old=snap(); cur=snap(endpoints=["/","/api","/admin"], technologies=["nginx","nextjs"], dependencies=["lodash@4.17.22"])
    diff=compare_snapshots(old,cur)
    assert diff["state"]=="changed"
    assert diff["endpoint_drift"]["added"]==["/admin"]
    assert diff["technology_drift"]["added"]==["nextjs"]
    assert diff["dependency_drift"]["added"]==["lodash@4.17.22"]

def test_no_drift():
    old=snap(); cur=snap(); assert compare_snapshots(old,cur)["state"]=="unchanged"

def test_shadow_assets_case_insensitive():
    assert detect_shadow_assets(["https://a.com"],["https://A.COM/","https://shadow.a.com"]) == ["https://shadow.a.com"]

def test_alerts():
    old=snap(); cur=snap(endpoints=["/","/new"])
    alerts=build_alerts(compare_snapshots(old,cur),asset_id="a1")
    assert [a["type"] for a in alerts]==["endpoint_drift"]
