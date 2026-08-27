from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any
import json

from harness.evaluation.metrics import evaluate_assessment


METRIC_NAMES = (
    "severity_accuracy",
    "evidence_coverage",
    "priority_range_score",
    "uncertainty_behavior",
    "unsupported_claim_rate",
)


def load_benchmark_cases(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())

    if not isinstance(data, list):
        raise ValueError("Benchmark file must contain a JSON array")

    case_ids: set[str] = set()

    for case in data:
        if not isinstance(case, dict):
            raise ValueError("Every benchmark case must be a JSON object")

        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("Every benchmark case needs a non-empty case_id")

        if case_id in case_ids:
            raise ValueError(f"Duplicate benchmark case_id: {case_id}")
        case_ids.add(case_id)

        if not isinstance(case.get("input_finding"), dict):
            raise ValueError(
                f"Benchmark case {case_id} is missing input_finding"
            )

        if not isinstance(case.get("expected"), dict):
            raise ValueError(
                f"Benchmark case {case_id} is missing expected"
            )

    return data


def index_benchmark_cases(
    cases: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    return {
        case["input_finding"]["finding_id"]: case
        for case in cases
    }


def evaluate_report(
    report: dict[str, Any],
    benchmark_cases: list[dict[str, Any]],
) -> dict[str, Any]:
    benchmark_by_finding = index_benchmark_cases(benchmark_cases)
    metric_values: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    case_results: list[dict[str, Any]] = []
    matched_finding_ids: set[str] = set()

    for finding_result in report.get("findings", []):
        finding = finding_result.get("finding", {})
        finding_id = finding.get("finding_id")
        case = benchmark_by_finding.get(finding_id)

        if case is None:
            continue

        matched_finding_ids.add(finding_id)
        expected = case["expected"]
        evidence_ids = {
            item["evidence_id"]
            for item in finding.get("evidence", [])
            if item.get("evidence_id")
        }
        human_review = bool(
            finding_result.get("consensus", {}).get(
                "requires_human_review",
                False,
            )
        )

        assessments = []
        for assessment in finding_result.get("assessments", []):
            provider_key = (
                f"{assessment.get('provider', 'unknown')}/"
                f"{assessment.get('model', 'unknown')}"
            )
            scores = evaluate_assessment(
                assessment,
                expected,
                evidence_ids,
            )
            scores["uncertainty_behavior"] = (
                float(
                    assessment.get("severity") == "unknown"
                    and human_review
                )
                if expected.get("severity") == "unknown"
                else 1.0
            )

            for metric_name, value in scores.items():
                metric_values[provider_key][metric_name].append(value)

            assessments.append(
                {
                    "provider": provider_key,
                    "scores": scores,
                }
            )

        case_results.append(
            {
                "case_id": case["case_id"],
                "finding_id": finding_id,
                "assessment_results": assessments,
                "report_warnings": finding_result.get(
                    "evaluator_warnings",
                    [],
                ),
            }
        )

    provider_metrics = {}
    for provider_key, values_by_metric in sorted(metric_values.items()):
        provider_metrics[provider_key] = {
            metric_name: round(
                mean(values_by_metric.get(metric_name, [0.0])),
                4,
            )
            for metric_name in METRIC_NAMES
        }
        provider_metrics[provider_key]["assessments_evaluated"] = len(
            values_by_metric.get("severity_accuracy", [])
        )

    unmatched_cases = sorted(
        case["case_id"]
        for case in benchmark_cases
        if case["input_finding"]["finding_id"] not in matched_finding_ids
    )

    benchmark_finding_ids = set(benchmark_by_finding)
    unmatched_report_findings = sorted(
        item.get("finding", {}).get("finding_id", "unknown")
        for item in report.get("findings", [])
        if item.get("finding", {}).get("finding_id")
        not in benchmark_finding_ids
    )

    return {
        "evaluation_version": "1.0",
        "source_report_run_id": report.get("run_id"),
        "benchmark_case_count": len(benchmark_cases),
        "matched_case_count": len(case_results),
        "provider_metrics": provider_metrics,
        "case_results": case_results,
        "unmatched_benchmark_cases": unmatched_cases,
        "unmatched_report_findings": unmatched_report_findings,
        "human_review_required": bool(unmatched_cases),
    }