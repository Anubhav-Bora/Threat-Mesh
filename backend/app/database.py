from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.config import Settings
from app.models import Base


def _normalize_asyncpg_url(url: str) -> str:
    url = url.strip()
    parsed = urlparse(url)
    if parsed.scheme not in {"postgresql", "postgresql+asyncpg", "postgres"}:
        return url

    scheme = "postgresql+asyncpg"
    params = parse_qsl(parsed.query, keep_blank_values=True)
    normalized: list[tuple[str, str]] = []
    ssl_mode: str | None = None
    had_ssl = False

    for key, value in params:
        lower_key = key.lower()
        if lower_key == "sslmode":
            ssl_mode = value.lower()
            continue
        if lower_key == "channel_binding":
            continue
        if lower_key == "ssl":
            had_ssl = True
            lower_value = value.lower()
            if lower_value in {"disable", "false", "0", "off"}:
                normalized.append((key, "disable"))
            elif lower_value in {"require", "true", "1", "on"}:
                normalized.append((key, "require"))
            else:
                normalized.append((key, value))
            continue
        normalized.append((key, value))

    if ssl_mode is not None and not had_ssl:
        if ssl_mode == "disable":
            normalized.append(("ssl", "disable"))
        elif ssl_mode:
            normalized.append(("ssl", ssl_mode))

    return urlunparse(
        (
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(normalized, doseq=True),
            parsed.fragment,
        )
    )


class Database:
    """Owns the async engine and session factory for one application instance."""

    def __init__(self, settings: Settings):
        database_url = _normalize_asyncpg_url(settings.database_url)
        engine_kwargs: dict[str, object] = {
            "echo": settings.database_echo,
            "pool_pre_ping": True,
        }
        if settings.database_url in {"sqlite+aiosqlite://", "sqlite+aiosqlite:///:memory:"}:
            engine_kwargs["poolclass"] = StaticPool
        self.engine: AsyncEngine = create_async_engine(database_url, **engine_kwargs)
        self.session_factory = async_sessionmaker(
            self.engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
        )

    async def create_schema(self) -> None:
        async with self.engine.begin() as connection:
            if self.engine.dialect.name == "postgresql":
                await connection.execute(text("CREATE EXTENSION IF NOT EXISTS postgis"))
            await connection.run_sync(Base.metadata.create_all)

    async def ping(self) -> None:
        async with self.engine.connect() as connection:
            await connection.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        await self.engine.dispose()

    async def session(self) -> AsyncIterator[AsyncSession]:
        async with self.session_factory() as session:
            yield session
