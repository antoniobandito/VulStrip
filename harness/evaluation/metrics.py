from __future__ import annotations

from typing import Any


def severity_accuracy(predicted: str, expected: str) -> float:
    return 1.0 if predicted == expected else 0.0


def evidence_coverage(
    cited_evidence: list[str],
    valid_evidence_ids: set[str],
) -> float:
    if not cited_evidence:
        return 0.0

    supported = sum(
        evidence_id in valid_evidence_ids
        for evidence_id in cited_evidence
    )
    return supported / len(cited_evidence)


def priority_range_score(
    priority: float,
    expected_range: tuple[float, float],
) -> float:
    lower, upper = expected_range

    if lower <= priority <= upper:
        return 1.0

    distance = lower - priority if priority < lower else priority - upper
    return max(0.0, 1.0 - distance / 100.0)


def uncertainty_behavior(
    severity: str,
    expected_severity: str,
    requires_human_review: bool,
) -> float:
    if expected_severity != "unknown":
        return 1.0

    return float(severity == "unknown" and requires_human_review)


def unsupported_claim_rate(assessment: dict[str, Any]) -> float:
    unsupported = assessment.get("unsafe_or_unsupported_claims", [])
    claims = assessment.get("claims", [])

    if not claims:
        return 0.0 if not unsupported else 1.0

    return min(1.0, len(unsupported) / len(claims))


def evaluate_assessment(
    assessment: dict[str, Any],
    expected: dict[str, Any],
    evidence_ids: set[str],
) -> dict[str, float]:
    expected_severity = expected.get("severity", "unknown")
    priority_range = expected.get("acceptable_priority_range", [0, 100])

    return {
        "severity_accuracy": severity_accuracy(
            assessment.get("severity", "unknown"),
            expected_severity,
        ),
        "evidence_coverage": evidence_coverage(
            assessment.get("cited_evidence", []),
            evidence_ids,
        ),
        "priority_range_score": priority_range_score(
            float(assessment.get("priority_score", 0.0)),
            (float(priority_range[0]), float(priority_range[1])),
        ),
        "uncertainty_behavior": uncertainty_behavior(
            assessment.get("severity", "unknown"),
            expected_severity,
            bool(expected.get("requires_human_review", False)),
        ),
        "unsupported_claim_rate": unsupported_claim_rate(assessment),
    }