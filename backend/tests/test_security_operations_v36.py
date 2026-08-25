from datetime import datetime, timedelta, timezone
from app.incident_response_v36 import Incident, IncidentManager, IncidentStatus, sla_breached

def test_incident_sla_and_assignment():
    m=IncidentManager(); i=m.create(Incident("INC-1",1,"Critical finding","critical"))
    assert i.status == "open" and i.due_at
    m.assign("INC-1","security@example.com")
    assert i.status == "in_progress" and i.owner == "security@example.com"

def test_suppression_and_fingerprint():
    m=IncidentManager(); i=Incident("INC-2",1,"Same issue","high",finding_keys=["F1"])
    m.suppress(i.fingerprint,"accepted duplicate")
    assert m.create(i).suppression_reason

def test_escalation_when_sla_breached():
    m=IncidentManager(); i=m.create(Incident("INC-3",1,"SLA","high",due_at=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()))
    assert sla_breached(i)
    assert m.escalate_due() and i.escalation_level == 1

def test_close_requires_remediation_done():
    m=IncidentManager(); m.create(Incident("INC-4",1,"Fix","medium"))
    t=m.add_remediation("INC-4","dev@example.com","fix issue")
    try: m.close_if_resolved("INC-4"); assert False
    except ValueError: pass
    t.status="completed"
    assert m.close_if_resolved("INC-4").status == IncidentStatus.closed.value

def test_transition_validation():
    m=IncidentManager(); m.create(Incident("INC-5",1,"x","low"))
    assert m.transition("INC-5","resolved").status == "resolved"
    try: m.transition("INC-5","bad"); assert False
    except ValueError: pass
