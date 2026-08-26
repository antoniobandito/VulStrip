from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ProviderConfig:
    provider_id: str
    provider_type: str
    model: str
    enabled: bool = False
    timeout_seconds: float = 10.0
    host: str | None = None


def load_provider_configs(path: Path) -> list[ProviderConfig]:
    data = yaml.safe_load(path.read_text()) or {}
    rows = data.get("providers", [])

    if not isinstance(rows, list):
        raise ValueError("providers must be a list")

    configs: list[ProviderConfig] = []
    seen_ids: set[str] = set()

    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each provider entry must be a mapping")

        provider_id = str(row.get("id", "")).strip()
        if not provider_id:
            raise ValueError("provider entry is missing id")
        if provider_id in seen_ids:
            raise ValueError(f"duplicate provider id: {provider_id}")
        seen_ids.add(provider_id)

        provider_type = str(row.get("type", "")).strip().lower()
        model = str(row.get("model", "")).strip()
        if provider_type not in {"mock", "ollama"}:
            raise ValueError(
                f"unsupported provider type: {provider_type}"
            )
        if not model:
            raise ValueError(f"provider {provider_id} is missing model")

        timeout = float(row.get("timeout_seconds", 10.0))
        if timeout <= 0:
            raise ValueError(
                f"provider {provider_id} timeout must be positive"
            )

        configs.append(
            ProviderConfig(
                provider_id=provider_id,
                provider_type=provider_type,
                model=model,
                enabled=bool(row.get("enabled", False)),
                timeout_seconds=timeout,
                host=row.get("host"),
            )
        )

    return configs