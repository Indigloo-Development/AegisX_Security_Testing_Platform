from app.services.enterprise import evaluate_security_gate


def test_security_gate_passes_without_critical_high():
    result = evaluate_security_gate(
        [{"severity": "medium"}, {"severity": "low"}],
        {"max_severity_counts": {"critical": 0, "high": 0}},
    )
    assert result["passed"] is True


def test_security_gate_blocks_high():
    result = evaluate_security_gate(
        [{"severity": "high"}],
        {"max_severity_counts": {"critical": 0, "high": 0}},
    )
    assert result["passed"] is False


def test_security_gate_counts_case_insensitive():
    result = evaluate_security_gate(
        [{"severity": "HIGH"}, {"severity": "high"}],
        {"max_severity_counts": {"high": 1}},
    )
    assert result["counts"]["high"] == 2
    assert result["passed"] is False
