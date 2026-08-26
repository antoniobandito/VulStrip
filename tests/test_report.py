import pytest

from harness.evaluation.orchestrator import assess_with_providers
from harness.evaluation.report import build_finding_report, build_report
from harness.models.finding import Evidence, Finding
from harness.providers.mock import MockProvider


def make_finding() -> Finding:
    return Finding(
        finding_id="f-report",
        asset="app.example.test",
        asset_type="domain",
        title="Report fixture",
        fingerprint="report-fingerprint",
        evidence=[
            Evidence(
                evidence_id="e-report",
                source_tool="test",
                raw_text="Evidence fixture",
            )
        ],
    )


@pytest.mark.asyncio
async def test_report_contains_one_assessment_per_successful_provider():
    finding = make_finding()
    providers = [
        MockProvider(model="mock-a"),
        MockProvider(model="mock-b"),
    ]

    results = await assess_with_providers(finding, providers)
    report = build_finding_report(finding, results)

    assert len(report["assessments"]) == 2
    assert {
        item["model"] for item in report["assessments"]
    } == {"mock-a", "mock-b"}
    assert report["consensus"]["assessment_count"] == 2


@pytest.mark.asyncio
async def test_report_preserves_timeout_warning():
    finding = make_finding()
    results = await assess_with_providers(
        finding,
        [
            MockProvider(model="fast"),
            MockProvider(model="slow", delay_seconds=0.05),
        ],
        timeout_seconds=0.001,
    )

    report = build_finding_report(finding, results)

    assert len(report["assessments"]) == 1
    assert any(
        "timed out" in warning
        for warning in report["evaluator_warnings"]
    )
    assert report["consensus"]["requires_human_review"] is True


@pytest.mark.asyncio
async def test_build_report_contains_run_metrics():
    finding = make_finding()
    results = await assess_with_providers(
        finding,
        [MockProvider(model="mock-a")],
    )

    report = build_report(
        [finding],
        {finding.finding_id: results},
        scope={"engagement_id": "test"},
        input_files=["fixture.json"],
    )

    assert report["report_version"] == "1.0"
    assert report["run_metrics"]["finding_count"] == 1
    assert report["run_metrics"]["assessment_count"] == 1
    assert report["providers"] == ["mock/mock-a"]


@pytest.mark.asyncio
async def test_unknown_mock_assessments_require_human_review():
    finding = make_finding()

    results = await assess_with_providers(
        finding,
        [MockProvider(model="mock-a")],
    )

    report = build_finding_report(finding, results)

    assert report["consensus"]["requires_human_review"] is True