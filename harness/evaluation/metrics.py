from __future__ import annotations

from typing import Any


def severity_accuracy(
    predicted: str,
    expected: str,
) -> float:
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


def unsupported_claim_rate(
    claims: list[str],
    unsupported_claims: list[str],
) -> float:
    if not claims:
        return 0.0

    return len(unsupported_claims) / len(claims)


def priority_range_score(
    priority: float,
    expected_range: tuple[float, float],
) -> float:
    lower, upper = expected_range

    if lower <= priority <= upper:
        return 1.0

    distance = (
        lower - priority
        if priority < lower
        else priority - upper
    )

    return max(0.0, 1.0 - distance / 100.0)

def evaluate_assessment(
    assessment: dict[str, Any],
    expected: dict[str, Any],
    evidence_ids: set[str],
) -> dict[str, float]:
    return {
        "severity_accuracy": severity_accuracy(
            assessment["severity"],
            expected["severity"],
        ),
        "evidence_coverage": evidence_coverage(
            assessment["cited_evidence"],
            evidence_ids,
        ),
        "priority_range_score": priority_range_score(
            assessment["priority_score"],
            tuple(expected["acceptable_priority_range"]),
        ),
        "uncertainty_behavior": float(
            assessment["severity"] == "unknown"
            if expected["severity"] == "unknown"
            else True
        ),
    }