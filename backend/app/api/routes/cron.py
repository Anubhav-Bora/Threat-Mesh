from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Header, Request

from app.errors import AppError
from app.maintenance import DataRetentionService
from app.pipeline import PipelineService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cron", tags=["cron"])


def _validate_cron_secret(request: Request, authorization: str | None) -> None:
    """Validate the Vercel cron secret.

    Vercel passes the secret as a Bearer token in the Authorization header.
    The endpoint also accepts it as a plain value for manual curl testing.
    If CRON_SECRET is not configured the endpoint is disabled entirely —
    an unconfigured cron endpoint is a security hole.
    """
    expected: str | None = request.app.state.settings.cron_secret
    if not expected:
        raise AppError(
            503,
            "cron_not_configured",
            "CRON_SECRET is not configured. Set it in your Vercel environment variables "
            "and in the backend settings before enabling the cron endpoint.",
        )
    provided = ""
    if authorization:
        # Vercel sends: Authorization: Bearer <secret>
        if authorization.lower().startswith("bearer "):
            provided = authorization[7:].strip()
        else:
            provided = authorization.strip()
    if not provided or not secrets.compare_digest(provided, expected):
        raise AppError(
            401,
            "invalid_cron_secret",
            "A valid Authorization: Bearer <CRON_SECRET> header is required",
        )


@router.api_route("/pipeline", methods=["GET", "POST"])
async def run_pipeline(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    """Full pipeline run triggered by Vercel cron.

    Runs feeds → enrichment → analysis in sequence and returns a summary.
    Vercel cron jobs hit this endpoint on the configured schedule with the
    CRON_SECRET in the Authorization header.

    To test manually:
        curl -X POST https://<your-deployment>.vercel.app/api/v1/cron/pipeline \\
             -H "Authorization: Bearer <CRON_SECRET>"
    """
    _validate_cron_secret(request, authorization)

    started_at = datetime.now(UTC)
    settings = request.app.state.settings
    session_factory = request.app.state.database.session_factory

    # Acquire all pipeline locks sequentially — if any job is currently
    # running (e.g. a concurrent manual trigger from Settings) this returns
    # 409 rather than running a second overlapping pipeline.
    feeds_lock = request.app.state.job_locks["feeds"]
    enrichment_lock = request.app.state.job_locks["enrichment"]
    analysis_lock = request.app.state.job_locks["analysis"]

    if feeds_lock.locked() or enrichment_lock.locked() or analysis_lock.locked():
        raise AppError(
            409,
            "pipeline_already_running",
            "A pipeline job is already running. The cron will retry on the next schedule.",
        )

    pipeline = PipelineService(session_factory, settings)

    async with feeds_lock:
        retention = await DataRetentionService(
            session_factory,
            settings.data_retention_days,
        ).purge_stale_records(started_at)

        from app.ingestion import IngestionService
        feeds_result = await IngestionService(session_factory, settings).sync_all()

    async with enrichment_lock:
        from app.enrichment import EnrichmentService
        enrichment_result = await EnrichmentService(session_factory, settings).enrich_pending()

    async with analysis_lock:
        analysis_result = await pipeline.run_analysis()

    completed_at = datetime.now(UTC)
    duration_seconds = round((completed_at - started_at).total_seconds(), 1)

    logger.info(
        "Cron pipeline completed in %.1fs: feeds=%s enrichment=%s analysis=%s",
        duration_seconds,
        feeds_result,
        enrichment_result,
        analysis_result,
    )

    return {
        "status": "completed",
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "duration_seconds": duration_seconds,
        "retention": retention,
        "feeds": feeds_result,
        "enrichment": enrichment_result,
        "analysis": analysis_result,
    }
