from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from app.errors import AppError
from app.genai.providers import (
    FallbackProvider,
    GeminiProvider,
    LLMProvider,
    LLMResponse,
    OpenRouterProvider,
    StaticProvider,
    build_provider,
)


class FailingGeminiModels:
    def __init__(self) -> None:
        self.calls = 0

    async def generate_content(self, **_kwargs):
        self.calls += 1
        raise httpx.ConnectError("provider unavailable")


class FakeAsyncGeminiClient:
    def __init__(self, models: FailingGeminiModels) -> None:
        self.models = models

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args) -> None:
        return None


class FailingGeminiClient:
    models = FailingGeminiModels()

    def __init__(self, **_kwargs) -> None:
        self.aio = FakeAsyncGeminiClient(self.models)

    def close(self) -> None:
        return None


@pytest.mark.asyncio
async def test_gemini_network_failures_are_retried_and_return_service_error(
    settings, monkeypatch
) -> None:
    settings.gemini_api_key = "test-key"
    settings.gemini_model = "test-model"
    FailingGeminiClient.models = FailingGeminiModels()
    sleep = AsyncMock()
    monkeypatch.setattr("app.genai.providers.genai.Client", FailingGeminiClient)
    monkeypatch.setattr("app.genai.providers.asyncio.sleep", sleep)

    with pytest.raises(AppError) as caught:
        await GeminiProvider(settings).generate("question", system_instruction="system")

    assert caught.value.status_code == 502
    assert caught.value.code == "llm_provider_error"
    assert caught.value.details == {"reason": "provider unavailable"}
    assert FailingGeminiClient.models.calls == 3
    assert sleep.await_count == 2


@pytest.mark.asyncio
async def test_openrouter_uses_backend_key_and_reports_resolved_model(settings) -> None:
    settings.openrouter_api_key = "test-openrouter-key"
    settings.openrouter_model = "openrouter/free"
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["authorization"] = request.headers.get("Authorization")
        captured["payload"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "model": "example/free-model",
                "choices": [{"message": {"content": "Grounded response"}}],
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await OpenRouterProvider(settings, client=client).generate(
            "question", system_instruction="system"
        )

    assert captured["authorization"] == "Bearer test-openrouter-key"
    assert '"model":"openrouter/free"' in str(captured["payload"])
    assert response == LLMResponse(
        text="Grounded response",
        provider="openrouter",
        model="example/free-model",
    )


class TransientFailingProvider(LLMProvider):
    name = "primary"
    model = "primary-model"

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        raise AppError(502, "llm_provider_error", "temporary failure")


@pytest.mark.asyncio
async def test_explicit_fallback_runs_after_transient_primary_failure() -> None:
    fallback = StaticProvider("Fallback response")
    response = await FallbackProvider(TransientFailingProvider(), fallback).generate(
        "question", system_instruction="system"
    )

    assert response.provider == "static"
    assert response.text == "Fallback response"
    assert fallback.prompts == ["system\nquestion"]


def test_missing_primary_key_can_use_explicit_configured_fallback(settings) -> None:
    settings.llm_provider = "gemini"
    settings.gemini_api_key = None
    settings.llm_fallback_provider = "openrouter"
    settings.openrouter_api_key = "test-openrouter-key"

    provider = build_provider(settings)

    assert isinstance(provider, OpenRouterProvider)
