from __future__ import annotations

import asyncio
from dataclasses import dataclass

from harness.models.finding import Finding, ModelAssessment
from harness.providers.base import LLMProvider
from harness.security.prompting import build_assessment_prompt
from harness.security.redaction import redact_finding
from harness.evaluation.validators import validate_assessment


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    model: str
    assessment: ModelAssessment | None
    warnings: list[str]
    error: str | None = None


async def assess_with_provider(
    finding: Finding,
    provider: LLMProvider,
    *,
    timeout_seconds: float = 10.0,
) -> ProviderResult:
    safe_finding, redactions, injection_flags = redact_finding(finding)
    system_prompt, user_prompt, _ = build_assessment_prompt(safe_finding)
    metadata = provider.metadata
    warnings = [
        f"Redactions applied: {', '.join(redactions)}"
        for _ in [0]
        if redactions
    ]

    if injection_flags:
        warnings.append(
            "Prompt-injection indicators: "
            + ", ".join(injection_flags)
        )

    try:
        assessment = await asyncio.wait_for(
            provider.assess(
                safe_finding,
                system_prompt,
                user_prompt,
            ),
            timeout=timeout_seconds,
        )
    except asyncio.TimeoutError:
        return ProviderResult(
            provider=metadata.provider,
            model=metadata.model,
            assessment=None,
            warnings=warnings,
            error=f"Provider timed out after {timeout_seconds} seconds",
        )
    except Exception as exc:
        return ProviderResult(
            provider=metadata.provider,
            model=metadata.model,
            assessment=None,
            warnings=warnings,
            error=f"Provider failed: {exc}",
        )

    validation = validate_assessment(safe_finding, assessment)
    warnings.extend(validation.warnings)

    return ProviderResult(
        provider=metadata.provider,
        model=metadata.model,
        assessment=assessment,
        warnings=warnings,
        error=None if validation.valid else "Assessment validation warnings",
    )


async def assess_with_providers(
    finding: Finding,
    providers: list[LLMProvider],
    *,
    timeout_seconds: float = 10.0,
) -> list[ProviderResult]:
    return list(
        await asyncio.gather(
            *(
                assess_with_provider(
                    finding,
                    provider,
                    timeout_seconds=timeout_seconds,
                )
                for provider in providers
            )
        )
    )