from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        database_url=f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}",
        environment="test",
        scheduler_enabled=False,
        auto_create_schema=True,
        trusted_hosts=["testserver"],
        cors_origins=["http://localhost:5173"],
        public_rate_limit_per_minute=10_000,
        ai_rate_limit_per_minute=10_000,
        admin_api_key="test-admin-key",
        llm_provider="disabled",
        geolocation_enabled=True,
    )


@pytest_asyncio.fixture
async def app(settings: Settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture
async def client(app) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as value:
        yield value
