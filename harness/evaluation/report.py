from __future__ import annotations

from datetime import datetime, timezone
from statistics import median
from typing import Any
import hashlib
import json
import uuid

from harness.evaluation.orchestrator import ProviderResult
from harness.models.finding import Finding


def build_finding_report(
    finding: Finding,
    results: list[ProviderResult],
) -> dict[str, Any]:
    assessments = [
        result.assessment.model_dump(mode="json")
        for result in results
        if result.assessment is not None
    ]

    warnings: list[str] = []
    for result in results:
        warnings.extend(
            f"{result.provider}/{result.model}: {warning}"
            for warning in result.warnings
        )
        if result.error:
            warnings.append(
                f"{result.provider}/{result.model}: {result.error}"
            )

    severities = [item["severity"] for item in assessments]
    priorities = [item["priority_score"] for item in assessments]
    confidences = [item["confidence"] for item in assessments]

    consensus: dict[str, Any] = {
        "assessment_count": len(assessments),
        "provider_count": len(results),
        "severity_values": sorted(set(severities)),
        "median_priority_score": median(priorities) if priorities else None,
        "priority_range": [min(priorities), max(priorities)] if priorities else [],
        "median_confidence": median(confidences) if confidences else None,
        "provider_agreement": _agreement(severities),
        "requires_human_review": (
            len(set(severities)) > 1
            or bool(warnings)
            or len(assessments) < len(results)
            or not assessments
            or all(
                item["severity"] == "unknown"
                and item["confidence"] == 0.0
                for item in assessments
            )
        ),
    }

    return {
        "finding": finding.model_dump(mode="json"),
        "assessments": assessments,
        "consensus": consensus,
        "disagreements": _disagreements(results),
        "evaluator_warnings": sorted(set(warnings)),
        "human_review": {
            "status": "pending",
            "reviewer": None,
            "notes": None,
        },
    }


def build_report(
    findings: list[Finding],
    results_by_finding: dict[str, list[ProviderResult]],
    *,
    scope: dict[str, Any],
    input_files: list[str],
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    finding_reports = [
        build_finding_report(
            finding,
            results_by_finding.get(finding.finding_id, []),
        )
        for finding in findings
    ]

    provider_failures = sum(
        1
        for results in results_by_finding.values()
        for result in results
        if result.error is not None
    )

    return {
        "report_version": "1.0",
        "run_id": run_id,
        "created_at": created_at,
        "scope": scope,
        "input_files": input_files,
        "providers": sorted(
            {
                f"{result.provider}/{result.model}"
                for results in results_by_finding.values()
                for result in results
            }
        ),
        "findings": finding_reports,
        "run_metrics": {
            "finding_count": len(findings),
            "assessment_count": sum(
                len(results)
                for results in results_by_finding.values()
            ),
            "provider_failures": provider_failures,
        },
    }


def _agreement(values: list[str]) -> float | None:
    if not values:
        return None
    return max(values.count(value) for value in set(values)) / len(values)


def _disagreements(results: list[ProviderResult]) -> list[str]:
    assessments = [
        result.assessment
        for result in results
        if result.assessment is not None
    ]
    disagreements: list[str] = []

    severities = {item.severity for item in assessments}
    if len(severities) > 1:
        disagreements.append(
            "Providers disagree on severity: "
            + ", ".join(sorted(severities))
        )

    if assessments:
        priorities = [item.priority_score for item in assessments]
        if max(priorities) - min(priorities) >= 20:
            disagreements.append(
                "Provider priority scores differ by at least 20 points."
            )

    return disagreements