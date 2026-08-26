from __future__ import annotations

import asyncio
import json
from pathlib import Path


from harness.providers.config import load_provider_configs
from harness.providers.registry import create_provider
from harness.providers.ollama import OllamaProvider
from harness.evaluation.orchestrator import assess_with_providers
from harness.evaluation.report import build_report
from harness.models.finding import Finding
from harness.providers.mock import MockProvider

provider_configs = [
    config
    for config in load_provider_configs(Path("providers.yaml"))
    if config.enabled
]

providers = [
    create_provider(config)
    for config in provider_configs
]

timeout_seconds = max(
    (config.timeout_seconds for config in provider_configs),
    default=10.0,
)

async def run(input_path: Path, output_path: Path) -> None:
    data = json.loads(input_path.read_text())
    findings = [Finding.model_validate(item) for item in data["findings"]]

    providers = [
        MockProvider(model="mock-a"),
        OllamaProvider(
            model="qwen3",
            host="http://localhost:11434"
        ),
    ]

    results_by_finding = {}
    for finding in findings:
        results_by_finding[finding.finding_id] = await assess_with_providers(
            finding,
            providers,
            timeout_seconds=10.0,
        )

    report = build_report(
        findings,
        results_by_finding,
        scope=data["scope"],
        input_files=data.get("input_files", []),
    )
    output_path.write_text(json.dumps(report, indent=2))


if __name__ == "__main__":
    asyncio.run(
        run(
            Path("normalized-findings.json"),
            Path("mock-report.json"),
        )
    )