from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.session import Base
from app.models.models import Organization, IncidentRecord
from app.enterprise_v37.service import create_incident, assign, add_remediation, change_status, ticket_payload, link_ticket, inbound_sync


def setup_db():
    engine=create_engine('sqlite:///:memory:', connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def test_persistent_incident_history_and_reopen():
    db=setup_db(); org=Organization(name='org-v37'); db.add(org); db.commit();
    rec=create_incident(db,org.id,'INC-V37-1','API access control','high',['F-1'])
    assign(db,rec,'owner@example.com',None)
    change_status(db,rec,'resolved',None)
    change_status(db,rec,'in_progress',None)
    rows=db.query(IncidentRecord).all(); assert len(rows)==1 and rows[0].status=='in_progress'

def test_ticket_adapters_and_sync():
    db=setup_db(); org=Organization(name='org-v37-b'); db.add(org); db.commit();
    rec=create_incident(db,org.id,'INC-V37-2','SCA issue','critical',[])
    payload=ticket_payload(rec,'jira'); assert payload.provider=='jira' and payload.external_key.startswith('AEGISX-')
    link=link_ticket(db,rec,'jira','SEC-42','In Progress','https://jira.local/browse/SEC-42',None); assert link.external_key=='SEC-42'
    inbound_sync(db,rec,'jira','resolved',None); assert rec.status=='resolved'

def test_close_requires_remediation():
    db=setup_db(); org=Organization(name='org-v37-c'); db.add(org); db.commit();
    rec=create_incident(db,org.id,'INC-V37-3','fix','medium',[])
    add_remediation(db,rec,'dev@example.com','patch',None,None)
    try:
        change_status(db,rec,'closed',None); assert False
    except ValueError: pass
