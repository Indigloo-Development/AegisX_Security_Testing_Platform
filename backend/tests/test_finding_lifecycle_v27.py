from app.lifecycle.service import evidence_fingerprint, snapshot_trend, upsert_lifecycle, compare_evidence
from app.lifecycle.models import FindingLifecycleStatus

def test_fingerprint_is_deterministic():
    assert evidence_fingerprint({"b":2,"a":1}) == evidence_fingerprint({"a":1,"b":2})

def test_lifecycle_first_seen_and_status(db_session):
    row = upsert_lifecycle(db_session, finding_key="AX-LC-1", status="open", evidence={"x": 1}, risk_score=70)
    assert row.status == FindingLifecycleStatus.open
    assert row.first_seen_at == row.last_seen_at
    row2 = upsert_lifecycle(db_session, finding_key="AX-LC-1", status="accepted_risk", evidence={"x": 2}, risk_score=20)
    assert row2.id == row.id
    assert row2.status == FindingLifecycleStatus.accepted_risk
    assert row2.last_seen_at >= row2.first_seen_at

def test_retest_fixed_then_reopened(db_session):
    upsert_lifecycle(db_session, finding_key="AX-LC-2", status="open", evidence={"marker":"a"})
    rec = compare_evidence(db_session, "AX-LC-2", {"marker":"b"})
    assert rec.result == "changed"
    rec2 = compare_evidence(db_session, "AX-LC-2", {"marker":"b"})
    assert rec2.result == "unchanged"

def test_snapshot_trend(db_session):
    row = snapshot_trend(db_session, "2026-08", [{"severity":"critical"},{"severity":"high"},{"severity":"low"}])
    assert row.total_findings == 3
    assert row.critical == 1
    assert row.high == 1
    assert row.low == 1
    assert row.risk_score == 17.0
