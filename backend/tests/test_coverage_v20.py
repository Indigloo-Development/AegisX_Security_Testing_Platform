from app.rules.engine import RuleEngine
from app.testlab import TestLabRunner as LabRunner
from app.testlab.coverage import build_coverage_matrix

def test_all_active_rules_are_covered():
    report=build_coverage_matrix()
    assert report['uncovered_rules']==0, report
    assert report['coverage_percent']==100.0

def test_all_coverage_fixtures_pass():
    results=LabRunner().run_all()
    failed=[r.as_dict() for r in results if not r.passed]
    assert not failed, failed[:10]

def test_catalog_and_coverage_consistent():
    keys={r.key for r in RuleEngine().list_rules()}
    covered=set(LabRunner().coverage()['rules'])
    assert keys==covered
