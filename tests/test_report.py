import pytest

from harness.evaluation.orchestrator import assess_with_providers
from harness.evaluation.report import build_finding_report, build_report
from harness.models.finding import Finding
from harness.providers.mock import MockProvider
from harness.models.finding import ModelAssessment, Evidence
from harness.providers.base import ProviderMetadata



def make_finding() -> Finding:
    return Finding(
        finding_id="f-report",
        asset_id="app.example.test",
        scanner="test",
        title="Report fixture",
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

class FixedProvider:
    def __init__(self, model: str, severity: str, priority: float):
        self.metadata = ProviderMetadata(
            provider="test",
            model=model,
            prompt_version="v1",
        )
        self.severity = severity
        self.priority = priority

    async def assess(self, finding, system_prompt, user_prompt):
        return ModelAssessment(
            provider="test",
            model=self.metadata.model,
            finding_id=finding.finding_id,
            severity=self.severity,
            priority_score=self.priority,
            exploitability="unknown",
            exploitability_reason="Fixture assessment only.",
            impact="unknown",
            confidence=0.5,
            recommended_actions=["Review the finding."],
            validation_steps=["Confirm with an authorized source."],
            assumptions=[],
            cited_evidence=[
                str(finding.evidence.get("evidence_id"))],
            unsafe_or_unsupported_claims=[],
            raw_response_hash="fixture-hash",
            prompt_version="v1",
        )

@pytest.mark.skip("disagreements / priority_range logic to be implemented")
@pytest.mark.asyncio 
async def test_report_surfaces_provider_disagreement():
    finding = make_finding()
    results = await assess_with_providers(
        finding,
        [
            FixedProvider("low-model", "low", 25),
            FixedProvider("high-model", "high", 85),
        ],
    )

    report = build_finding_report(finding, results)

    assert report["consensus"]["provider_agreement"] is None
    assert report["consensus"]["priority_range"] == []
    assert report["consensus"]["requires_human_review"] is True
    assert report["disagreements"]