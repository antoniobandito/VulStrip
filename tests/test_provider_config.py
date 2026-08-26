from pathlib import Path

import pytest

from harness.providers.config import load_provider_configs
from harness.providers.registry import check_provider_health


def test_loads_enabled_and_disabled_providers(tmp_path: Path):
    path = tmp_path / "providers.yaml"
    path.write_text(
        """
providers:
  - id: mock-a
    type: mock
    model: mock-a
    enabled: true
  - id: ollama-qwen
    type: ollama
    model: qwen3
    host: http://127.0.0.1:11434
    enabled: false
    timeout_seconds: 30
"""
    )

    configs = load_provider_configs(path)

    assert len(configs) == 2
    assert configs[0].enabled is True
    assert configs[1].enabled is False
    assert configs[1].timeout_seconds == 30


def test_rejects_duplicate_provider_ids(tmp_path: Path):
    path = tmp_path / "providers.yaml"
    path.write_text(
        """
providers:
  - id: duplicate
    type: mock
    model: a
  - id: duplicate
    type: mock
    model: b
"""
    )

    with pytest.raises(ValueError, match="duplicate provider id"):
        load_provider_configs(path)


def test_disabled_provider_health_is_explicit(tmp_path: Path):
    path = tmp_path / "providers.yaml"
    path.write_text(
        """
providers:
  - id: ollama-qwen
    type: ollama
    model: qwen3
    enabled: false
"""
    )

    config = load_provider_configs(path)[0]
    health = check_provider_health(config)

    assert health.available is False
    assert health.message == "Provider disabled by configuration"