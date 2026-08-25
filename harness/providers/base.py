from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from harness.models.finding import Finding, ModelAssessment


@dataclass(frozen=True)
class ProviderMetadata:
    provider: str
    model: str
    prompt_version: str = "v1"


class LLMProvider(Protocol):
    metadata: ProviderMetadata

    async def assess(
        self,
        finding: Finding,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelAssessment:
        ...