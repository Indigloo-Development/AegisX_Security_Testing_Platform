from app.testlab import all_fixtures, fixture_counts, TestLabRunner as LabRunner


def test_lab_has_positive_and_negative_corpus():
    counts = fixture_counts()
    assert counts['total'] >= 100
    assert counts['positive'] > 0
    assert counts['negative'] > 0


def test_lab_registry_unique_ids():
    ids = [f.fixture_id for f in all_fixtures()]
    assert len(ids) == len(set(ids))


def test_negative_fixture_has_no_expected_rules():
    for fixture in all_fixtures():
        if fixture.negative:
            assert fixture.expected_rules == ()
            assert fixture.forbidden_rules


def test_selected_detector_fixtures_pass():
    runner = LabRunner()
    sample_ids = ['WEB-REFLECT-01','WEB-SSRF-01','API-BOLA-01','AUTH-SESSION-01']
    results = [runner.run_fixture(next(f for f in all_fixtures() if f.fixture_id == fid)) for fid in sample_ids]
    assert all(r.passed for r in results), [r.as_dict() for r in results]


def test_lab_coverage_report():
    coverage = LabRunner().coverage()
    assert coverage['fixtures'] >= 100
    assert coverage['covered_rules'] > 0
