import asyncio

import pytest

from harness.models.finding import Evidence, Finding
from harness.providers.mock import MockProvider
from harness.evaluation.orchestrator import (
    assess_with_provider,
    assess_with_providers,
)


def make_finding() -> Finding:
    return Finding(
        finding_id="f-test",
        asset="app.example.test",
        asset_type="domain",
        title="Example scanner observation",
        fingerprint="fingerprint-test",
        evidence=[
            Evidence(
                evidence_id="e-test",
                source_tool="test",
                raw_text="Observed by test fixture",
            )
        ],
    )


@pytest.mark.asyncio
async def test_mock_provider_returns_valid_assessment():
    result = await assess_with_provider(
        make_finding(),
        MockProvider(),
    )

    assert result.error is None
    assert result.assessment is not None
    assert result.assessment.provider == "mock"
    assert result.assessment.finding_id == "f-test"
    assert result.assessment.cited_evidence == ["e-test"]


@pytest.mark.asyncio
async def test_provider_timeout_is_captured():
    result = await assess_with_provider(
        make_finding(),
        MockProvider(delay_seconds=0.05),
        timeout_seconds=0.001,
    )

    assert result.assessment is None
    assert result.error is not None
    assert "timed out" in result.error


@pytest.mark.asyncio
async def test_multiple_providers_run_in_parallel():
    results = await assess_with_providers(
        make_finding(),
        [MockProvider(model="mock-a"), MockProvider(model="mock-b")],
    )

    assert len(results) == 2
    assert {item.model for item in results} == {"mock-a", "mock-b"}


@pytest.mark.asyncio
async def test_invalid_provider_failure_is_captured():
    result = await assess_with_provider(
        make_finding(),
        MockProvider(invalid_response=True),
    )

    assert result.assessment is None
    assert result.error is not None
    assert "invalid structured output" in result.error