from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.attack_mapping import AttackMappingService
from app.config import Settings, get_settings
from app.database import Database
from app.errors import AppError, install_error_handlers
from app.logging import configure_logging
from app.middleware import (
    PublicRateLimitMiddleware,
    SecurityAndObservabilityMiddleware,
    SlidingWindowRateLimiter,
)
from app.scheduler import SchedulerManager


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    configure_logging(resolved.log_level, json_logs=resolved.is_production)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        database = Database(resolved)
        application.state.database = database
        if resolved.auto_create_schema:
            await database.create_schema()
        await AttackMappingService(database.session_factory).seed_curated_techniques()
        scheduler = SchedulerManager(
            database.session_factory, resolved, application.state.job_locks
        )
        application.state.scheduler_manager = scheduler
        if resolved.scheduler_enabled:
            scheduler.start()
        try:
            yield
        finally:
            await scheduler.shutdown()
            await database.dispose()

    app = FastAPI(
        title=resolved.app_name,
        version=resolved.app_version,
        description=(
            "Passive OSINT ingestion, geographic enrichment, graph analysis, detection content, "
            "and retrieval-grounded CTI reporting."
        ),
        debug=resolved.debug,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )
    app.state.settings = resolved
    app.state.rate_limiter = SlidingWindowRateLimiter()
    app.state.job_locks = {
        "feeds": asyncio.Lock(),
        "enrichment": asyncio.Lock(),
        "analysis": asyncio.Lock(),
        "reports": asyncio.Lock(),
    }

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "X-API-Key", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=resolved.trusted_hosts)
    app.add_middleware(
        PublicRateLimitMiddleware,
        limiter=app.state.rate_limiter,
        limit=resolved.public_rate_limit_per_minute,
    )
    # Added last so request IDs exist even for responses rejected by inner middleware.
    app.add_middleware(SecurityAndObservabilityMiddleware)

    health_router = APIRouter(tags=["health"])

    @health_router.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": resolved.app_name,
            "version": resolved.app_version,
            "environment": resolved.environment,
            "timestamp": datetime.now(UTC),
        }

    @health_router.get("/ready")
    async def ready(request: Request) -> dict[str, Any]:
        try:
            async with asyncio.timeout(3):
                await request.app.state.database.ping()
        except Exception as exc:
            raise AppError(
                503,
                "database_not_ready",
                "The database is not ready",
                details={"reason": str(exc)[:200]} if resolved.debug else None,
            ) from exc
        ai_provider = resolved.llm_provider.lower()
        ai_configured = ai_provider == "ollama" or (
            ai_provider == "gemini" and bool(resolved.gemini_api_key)
        )
        return {
            "status": "ready",
            "database": "ok",
            "scheduler": "running"
            if resolved.scheduler_enabled and request.app.state.scheduler_manager.scheduler.running
            else "disabled",
            "ai": {"provider": ai_provider, "configured": ai_configured},
        }

    app.include_router(health_router)
    app.include_router(health_router, prefix=resolved.api_v1_prefix, include_in_schema=False)
    app.include_router(api_router, prefix=resolved.api_v1_prefix)
    install_error_handlers(app)
    return app


app = create_app()
