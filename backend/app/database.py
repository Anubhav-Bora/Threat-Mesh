from __future__ import annotations

from collections.abc import AsyncIterator

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


class Database:
    """Owns the async engine and session factory for one application instance."""

    def __init__(self, settings: Settings):
        engine_kwargs: dict[str, object] = {
            "echo": settings.database_echo,
            "pool_pre_ping": True,
        }
        if settings.database_url in {"sqlite+aiosqlite://", "sqlite+aiosqlite:///:memory:"}:
            engine_kwargs["poolclass"] = StaticPool
        self.engine: AsyncEngine = create_async_engine(settings.database_url, **engine_kwargs)
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
