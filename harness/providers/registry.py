from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.error import URLError
from urllib.request import urlopen

from harness.providers.base import LLMProvider
from harness.providers.config import ProviderConfig
from harness.providers.mock import MockProvider
from harness.providers.ollama import OllamaProvider


@dataclass(frozen=True)
class ProviderHealth:
    provider_id: str
    provider_type: str
    model: str
    enabled: bool
    available: bool
    message: str


def create_provider(config: ProviderConfig) -> LLMProvider:
    if config.provider_type == "mock":
        return MockProvider(model=config.model)

    if config.provider_type == "ollama":
        return OllamaProvider(
            model=config.model,
            host=config.host or "http://localhost:11434",
        )

    raise ValueError(f"Unsupported provider type: {config.provider_type}")


def check_ollama_health(
    config: ProviderConfig,
    *,
    timeout_seconds: float = 2.0,
) -> ProviderHealth:
    base_url = (config.host or "http://localhost:11434").rstrip("/")

    try:
        with urlopen(
            f"{base_url}/api/tags",
            timeout=timeout_seconds,
        ) as response:
            if response.status != 200:
                return ProviderHealth(
                    config.provider_id,
                    config.provider_type,
                    config.model,
                    config.enabled,
                    False,
                    f"health endpoint returned HTTP {response.status}",
                )

        return ProviderHealth(
            config.provider_id,
            config.provider_type,
            config.model,
            config.enabled,
            True,
            "Ollama API reachable",
        )
    except Exception as exc:
        return ProviderHealth(
            config.provider_id,
            config.provider_type,
            config.model,
            config.enabled,
            False,
            f"Ollama unavailable: {exc}",
        )


def check_provider_health(
    config: ProviderConfig,
) -> ProviderHealth:
    if not config.enabled:
        return ProviderHealth(
            config.provider_id,
            config.provider_type,
            config.model,
            False,
            False,
            "Provider disabled by configuration",
        )

    if config.provider_type == "mock":
        return ProviderHealth(
            config.provider_id,
            config.provider_type,
            config.model,
            True,
            True,
            "Mock provider available",
        )

    return check_ollama_health(config)