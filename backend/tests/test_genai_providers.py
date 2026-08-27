from __future__ import annotations

from unittest.mock import AsyncMock

import httpx
import pytest

from app.errors import AppError
from app.genai.providers import GeminiProvider


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
