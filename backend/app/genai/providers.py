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
                if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                    break
                await asyncio.sleep(1.0 * (2**attempt))
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 2:
                    break
                await asyncio.sleep(1.0 * (2**attempt))
            finally:
                client.close()
        reason = str(last_error).strip() or type(last_error).__name__
        raise AppError(
            502,
            "llm_provider_error",
            "Gemini could not generate a response",
            details={"reason": reason[:300]},
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


class OpenRouterProvider(LLMProvider):
    name = "openrouter"

    def __init__(self, settings: Settings, *, client: httpx.AsyncClient | None = None) -> None:
        if not settings.openrouter_api_key:
            raise AppError(
                503,
                "llm_not_configured",
                "OpenRouter is selected but OPENROUTER_API_KEY is not configured",
                details={
                    "setup": "Create an OpenRouter API key and set OPENROUTER_API_KEY. "
                    "The openrouter/free model is best-effort and rate-limited."
                },
            )
        self.api_key = settings.openrouter_api_key
        self.model = settings.openrouter_model
        self.base_url = settings.openrouter_base_url.rstrip("/")
        self.site_url = settings.openrouter_site_url
        self.app_name = settings.openrouter_app_name
        self.timeout = settings.llm_timeout_seconds
        self._client = client

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.timeout)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-OpenRouter-Title": self.app_name,
        }
        if self.site_url:
            headers["HTTP-Referer"] = self.site_url
        last_error: Exception | None = None
        try:
            for attempt in range(3):
                try:
                    response = await client.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json={
                            "model": self.model,
                            "messages": [
                                {"role": "system", "content": system_instruction},
                                {"role": "user", "content": prompt},
                            ],
                            "temperature": 0.1,
                            "max_tokens": 4096,
                        },
                    )
                    response.raise_for_status()
                    payload = response.json()
                    choices = payload.get("choices")
                    message = (
                        choices[0].get("message") if isinstance(choices, list) and choices else None
                    )
                    text = message.get("content") if isinstance(message, dict) else None
                    if not isinstance(text, str) or not text.strip():
                        raise AppError(
                            502,
                            "empty_llm_response",
                            "OpenRouter returned no text",
                        )
                    resolved_model = payload.get("model")
                    return LLMResponse(
                        text=text.strip(),
                        provider=self.name,
                        model=resolved_model if isinstance(resolved_model, str) else self.model,
                    )
                except AppError:
                    raise
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    last_error = exc
                    retryable = not isinstance(
                        exc, httpx.HTTPStatusError
                    ) or exc.response.status_code in {
                        429,
                        500,
                        502,
                        503,
                        504,
                    }
                    if not retryable or attempt == 2:
                        break
                    await asyncio.sleep(1.0 * (2**attempt))
        finally:
            if owns_client:
                await client.aclose()
        reason = str(last_error).strip() or type(last_error).__name__
        raise AppError(
            502,
            "llm_provider_error",
            "OpenRouter could not generate a response",
            details={"reason": reason[:300]},
        )


class FallbackProvider(LLMProvider):
    """Use an explicitly configured second provider after a transient primary failure."""

    def __init__(self, primary: LLMProvider, fallback: LLMProvider) -> None:
        self.primary = primary
        self.fallback = fallback
        self.name = primary.name
        self.model = primary.model

    async def generate(self, prompt: str, *, system_instruction: str) -> LLMResponse:
        try:
            return await self.primary.generate(prompt, system_instruction=system_instruction)
        except AppError as exc:
            if exc.code not in {"empty_llm_response", "llm_provider_error"}:
                raise
            return await self.fallback.generate(prompt, system_instruction=system_instruction)


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


def _build_named_provider(provider: str, settings: Settings) -> LLMProvider:
    if provider == "gemini":
        return GeminiProvider(settings)
    if provider == "ollama":
        return OllamaProvider(settings)
    if provider == "openrouter":
        return OpenRouterProvider(settings)
    if provider in {"disabled", "none", "off"}:
        raise AppError(
            503,
            "llm_disabled",
            "AI generation is disabled until LLM_PROVIDER is set to gemini, ollama, or openrouter",
            details={
                "setup": "Set LLM_PROVIDER=gemini plus GEMINI_API_KEY, use local Ollama, "
                "or set LLM_PROVIDER=openrouter plus OPENROUTER_API_KEY."
            },
        )
    raise AppError(
        503,
        "invalid_llm_provider",
        "LLM provider must be gemini, ollama, openrouter, or disabled",
    )


def provider_is_configured(provider: str, settings: Settings) -> bool:
    normalized = provider.lower().strip()
    if normalized == "gemini":
        return bool(settings.gemini_api_key)
    if normalized == "openrouter":
        return bool(settings.openrouter_api_key)
    return normalized == "ollama"


def build_provider(settings: Settings) -> LLMProvider:
    provider_name = settings.llm_provider.lower().strip()
    fallback_name = settings.llm_fallback_provider.lower().strip()
    fallback_enabled = fallback_name not in {"", "disabled", "none", "off"}
    if fallback_enabled and fallback_name == provider_name:
        raise AppError(
            503,
            "invalid_llm_provider",
            "LLM_FALLBACK_PROVIDER must be different from LLM_PROVIDER",
        )

    try:
        primary = _build_named_provider(provider_name, settings)
    except AppError as exc:
        if not fallback_enabled or exc.code != "llm_not_configured":
            raise
        return _build_named_provider(fallback_name, settings)

    if not fallback_enabled:
        return primary
    return FallbackProvider(primary, _build_named_provider(fallback_name, settings))
