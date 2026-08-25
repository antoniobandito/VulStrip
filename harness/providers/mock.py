from __future__ import annotations

import asyncio
import hashlib
import json

from harness.models.finding import Finding, ModelAssessment
from harness.providers.base import ProviderMetadata


class MockProvider:
    def __init__(
        self,
        *,
        model: str = "mock-v1",
        delay_seconds: float = 0.0,
        invalid_response: bool = False,
    ) -> None:
        self.metadata = ProviderMetadata(
            provider="mock",
            model=model,
            prompt_version="v1",
        )
        self.delay_seconds = delay_seconds
        self.invalid_response = invalid_response

    async def assess(
        self,
        finding: Finding,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelAssessment:
        if self.delay_seconds:
            await asyncio.sleep(self.delay_seconds)

        if self.invalid_response:
            raise ValueError("Mock provider returned invalid structured output")

        cited_evidence = [
            evidence.evidence_id
            for evidence in finding.evidence
        ]

        raw_payload = {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "evidence": cited_evidence,
        }
        raw_response = json.dumps(
            raw_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        raw_response_hash = hashlib.sha256(
            raw_response.encode()
        ).hexdigest()

        return ModelAssessment(
            provider=self.metadata.provider,
            model=self.metadata.model,
            finding_id=finding.finding_id,
            severity="unknown",
            priority_score=0.0,
            exploitability="unknown",
            exploitability_reason=(
                "Mock assessment does not infer exploitability."
            ),
            impact="unknown",
            confidence=0.0,
            recommended_actions=[
                "Review the supplied reconnaissance evidence manually."
            ],
            validation_steps=[
                "Confirm the observation using an authorized source."
            ],
            assumptions=[],
            cited_evidence=cited_evidence,
            unsafe_or_unsupported_claims=[],
            raw_response_hash=raw_response_hash,
            prompt_version=self.metadata.prompt_version,
        )