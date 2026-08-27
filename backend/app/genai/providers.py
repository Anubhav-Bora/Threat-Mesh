from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass

import httpx
from google import genai
from google.genai import errors, types

from app.config import Settings
from app.errors import AppError


@dataclass(frozen=True)
class LLMResponse:
    text: str
    provider: str
    model: str


class LLMProvider(ABC):
    name: str
    model: str

    @abstractmethod
    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        raise NotImplementedError


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, settings: Settings) -> None:
        if not settings.gemini_api_key:
            raise AppError(
                503,
                "llm_not_configured",
                "Gemini is selected but GEMINI_API_KEY is not configured",
                details={
                    "setup": "Create a free key in Google AI Studio and set GEMINI_API_KEY, "
                    "or set LLM_PROVIDER=ollama for local inference."
                },
            )
        self.api_key = settings.gemini_api_key
        self.model = settings.gemini_model
        self.timeout = settings.llm_timeout_seconds

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        last_error: Exception | None = None
        for attempt in range(3):
            client = genai.Client(
                api_key=self.api_key,
                http_options=types.HttpOptions(timeout=int(self.timeout * 1000)),
            )
            try:
                async with client.aio as async_client:
                    response = await async_client.models.generate_content(
                        model=self.model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=system_instruction,
                            max_output_tokens=4096,
                        ),
                    )
                text = (response.text or "").strip()
                if not text:
                    raise AppError(502, "empty_llm_response", "Gemini returned no text")
                return LLMResponse(text=text, provider=self.name, model=self.model)
            except errors.APIError as exc:
                last_error = exc
                if exc.code != 429 or attempt == 2:
                    break
                await asyncio.sleep(1.0 * (2**attempt))
            finally:
                client.close()
        raise AppError(
            502,
            "llm_provider_error",
            "Gemini could not generate a response",
            details={"reason": str(last_error)[:300]},
        )


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.model = settings.ollama_model
        self.timeout = settings.llm_timeout_seconds
        self._client = client

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        try:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "system": system_instruction,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1},
                },
            )
            response.raise_for_status()
            text = str(response.json().get("response") or "").strip()
            if not text:
                raise AppError(502, "empty_llm_response", "Ollama returned no text")
            return LLMResponse(text=text, provider=self.name, model=self.model)
        except httpx.HTTPError as exc:
            raise AppError(
                502,
                "llm_provider_error",
                "The configured Ollama server is unavailable",
                details={"reason": str(exc)[:300]},
            ) from exc
        finally:
            if owns_client:
                await client.aclose()


class StaticProvider(LLMProvider):
    """Deterministic provider used only through explicit dependency injection in tests."""

    name = "static"
    model = "test-double"

    def __init__(self, response: str = "Grounded test response") -> None:
        self.response = response
        self.prompts: list[str] = []

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        self.prompts.append(f"{system_instruction}\n{prompt}")
        return LLMResponse(text=self.response, provider=self.name, model=self.model)


def build_provider(settings: Settings) -> LLMProvider:
    provider = settings.llm_provider.lower().strip()
    if provider == "gemini":
        return GeminiProvider(settings)
    if provider == "ollama":
        return OllamaProvider(settings)
    if provider in {"disabled", "none", "off"}:
        raise AppError(
            503,
            "llm_disabled",
            "AI generation is disabled until LLM_PROVIDER is set to 'gemini' or 'ollama'",
            details={
                "setup": "For Gemini, create a free Google AI Studio key and set "
                "LLM_PROVIDER=gemini plus GEMINI_API_KEY."
            },
        )
    raise AppError(
        503,
        "invalid_llm_provider",
        "LLM_PROVIDER must be either 'gemini' or 'ollama'",
    )
