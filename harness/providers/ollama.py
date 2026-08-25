from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from harness.models.finding import Finding, ModelAssessment
from harness.providers.base import ProviderMetadata


class OllamaProvider:
    def __init__(
        self,
        *,
        model: str = "qwen3",
        host: str = "http://localhost:11434",
        temperature: float = 0.0,
        client: Any | None = None,
    ) -> None:
        self.metadata = ProviderMetadata(
            provider="ollama",
            model=model,
            prompt_version="v1",
        )
        self.temperature = temperature

        if client is not None:
            self._client = client
        else:
            from ollama import AsyncClient

            self._client = AsyncClient(host=host)

    async def assess(
        self,
        finding: Finding,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelAssessment:
        response = await self._client.chat(
            model=self.metadata.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            format=ModelAssessment.model_json_schema(),
            options={
                "temperature": self.temperature,
            },
            stream=False,
        )

        raw_content = self._response_content(response)
        raw_response_hash = hashlib.sha256(
            raw_content.encode()
        ).hexdigest()

        try:
            assessment = ModelAssessment.model_validate_json(raw_content)
        except ValidationError as exc:
            raise ValueError(
                f"Ollama returned schema-invalid assessment: {exc}"
            ) from exc

        if assessment.finding_id != finding.finding_id:
            raise ValueError(
                "Ollama assessment finding_id does not match the input"
            )

        return assessment.model_copy(
            update={
                "provider": self.metadata.provider,
                "model": self.metadata.model,
                "raw_response_hash": raw_response_hash,
                "prompt_version": self.metadata.prompt_version,
            }
        )

    @staticmethod
    def _response_content(response: Any) -> str:
        if isinstance(response, dict):
            message = response.get("message", {})
            if isinstance(message, dict):
                content = message.get("content")
            else:
                content = getattr(message, "content", None)
        else:
            message = getattr(response, "message", None)
            content = getattr(message, "content", None)

        if not isinstance(content, str) or not content.strip():
            raise ValueError("Ollama response did not contain message content")

        return content