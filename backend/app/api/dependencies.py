from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings
from app.errors import AppError


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    async with request.app.state.database.session_factory() as session:
        yield session


async def require_admin(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    settings: Settings = request.app.state.settings
    expected = settings.admin_api_key
    if not expected:
        if settings.is_production:
            raise AppError(
                503,
                "admin_auth_not_configured",
                "Administrative operations are disabled until ADMIN_API_KEY is configured",
            )
        return
    if not x_api_key or not secrets.compare_digest(x_api_key, expected):
        raise AppError(401, "invalid_api_key", "A valid X-API-Key header is required")


def enforce_ai_rate_limit(request: Request) -> None:
    settings: Settings = request.app.state.settings
    client = request.client.host if request.client else "unknown"
    allowed, retry_after = request.app.state.rate_limiter.check(
        f"ai:{client}", settings.ai_rate_limit_per_minute
    )
    if not allowed:
        raise AppError(
            429,
            "ai_rate_limit_exceeded",
            "AI request limit exceeded",
            details={"retry_after_seconds": retry_after},
        )


SessionDep = Annotated[AsyncSession, Depends(get_session)]
SettingsDep = Annotated[Settings, Depends(get_app_settings)]
AdminDep = Annotated[None, Depends(require_admin)]
AIRateLimitDep = Annotated[None, Depends(enforce_ai_rate_limit)]
