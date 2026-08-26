from harness.evaluation.metrics import (
    evidence_coverage,
    priority_range_score,
    severity_accuracy,
)


def test_severity_accuracy():
    assert severity_accuracy("high", "high") == 1.0
    assert severity_accuracy("low", "high") == 0.0


def test_evidence_coverage():
    assert evidence_coverage(
        ["e-1", "e-2"],
        {"e-1", "e-2"},
    ) == 1.0

    assert evidence_coverage(
        ["e-1", "e-missing"],
        {"e-1"},
    ) == 0.5


def test_priority_range_score():
    assert priority_range_score(25, (0, 50)) == 1.0
    assert priority_range_score(100, (0, 50)) == 0.5