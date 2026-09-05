import json

import pytest

from harness.models.finding import Finding, Evidence
from harness.providers.ollama import OllamaProvider


class FakeOllamaClient:
    def __init__(self, content: str):
        self.content = content
        self.calls = []

    async def chat(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "message": {
                "content": self.content,
            }
        }


def make_finding() -> Finding:
    return Finding(
        finding_id="f-ollama-test",
        asset_id="app.example.test",
        scanner="test",
        title="Service observed",
        evidence=[
            Evidence(
                evidence_id="e-ollama-test",
                source_tool="test",
                raw_text="Observed by fixture",
            )
        ],
    )


def valid_content() -> str:
    return json.dumps(
        {
            "provider": "placeholder",
            "model": "placeholder",
            "finding_id": "f-ollama-test",
            "severity": "unknown",
            "priority_score": 0,
            "exploitability": "unknown",
            "exploitability_reason": "Evidence is insufficient.",
            "impact": "unknown",
            "confidence": 0,
            "recommended_actions": ["Review the evidence."],
            "validation_steps": ["Confirm through an authorized source."],
            "assumptions": [],
            "cited_evidence": ["e-ollama-test"],
            "unsafe_or_unsupported_claims": [],
            "raw_response_hash": "provider-value-is-replaced",
            "prompt_version": "provider-value-is-replaced",
        }
    )


@pytest.mark.asyncio
async def test_ollama_uses_schema_and_validates_response():
    client = FakeOllamaClient(valid_content())
    provider = OllamaProvider(client=client, model="qwen3")

    result = await provider.assess(
        make_finding(),
        "system",
        "user",
    )

    assert result.provider == "ollama"
    assert result.model == "qwen3"
    assert result.finding_id == "f-ollama-test"
    assert len(result.raw_response_hash) == 64

    request = client.calls[0]
    assert request["stream"] is False
    assert request["options"]["temperature"] == 0.0
    assert request["format"]["type"] == "object"
    assert "severity" in request["format"]["properties"]


@pytest.mark.asyncio
async def test_ollama_rejects_invalid_json():
    client = FakeOllamaClient("not-json")
    provider = OllamaProvider(client=client)

    with pytest.raises(ValueError, match="schema-invalid"):
        await provider.assess(make_finding(), "system", "user")


@pytest.mark.asyncio
async def test_ollama_rejects_wrong_finding_id():
    payload = json.loads(valid_content())
    payload["finding_id"] = "f-wrong"
    client = FakeOllamaClient(json.dumps(payload))
    provider = OllamaProvider(client=client)

    with pytest.raises(ValueError, match="finding_id"):
        await provider.assess(make_finding(), "system", "user")