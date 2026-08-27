from __future__ import annotations

import asyncio
import json
from pathlib import Path

from harness.evaluation.orchestrator import assess_with_providers
from harness.evaluation.report import build_report
from harness.models.finding import Finding
from harness.providers.config import load_provider_configs
from harness.providers.registry import create_provider


async def run(input_path: Path, config_path: Path, output_path: Path):
    input_data = json.loads(input_path.read_text())
    findings = [
        Finding.model_validate(item)
        for item in input_data["findings"]
    ]

    configs = [
        config
        for config in load_provider_configs(config_path)
        if config.enabled
    ]

    providers = [create_provider(config) for config in configs]
    timeout = max(
        (config.timeout_seconds for config in configs),
        default=10.0,
    )

    results_by_finding = {}
    for finding in findings:
        results_by_finding[finding.finding_id] = (
            await assess_with_providers(
                finding,
                providers,
                timeout_seconds=timeout,
            )
        )

    report = build_report(
        findings,
        results_by_finding,
        scope=input_data["scope"],
        input_files=input_data.get("input_files", []),
    )
    output_path.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(
        run(
            Path("normalized-findings.json"),
            Path("providers.yaml"),
            Path("provider-comparison.json"),
        )
    )