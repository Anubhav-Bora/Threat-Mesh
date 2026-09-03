from __future__ import annotations

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.api.dependencies import AdminDep, SessionDep
from app.api.schemas import OperationResult
from app.enrichment import EnrichmentService
from app.errors import AppError
from app.ingestion import IngestionService
from app.models import FeedRun, FeedRunStatus
from app.pipeline import PipelineService

router = APIRouter(tags=["pipeline operations"])


def _require_embedded_pipeline_control(request: Request) -> None:
    if request.app.state.settings.external_scheduler_enabled:
        raise AppError(
            409,
            "pipeline_externally_managed",
            "Pipeline mutations are owned by the external coordinator in this deployment.",
        )


async def _enter_job(request: Request, name: str):
    lock = request.app.state.job_locks[name]
    if lock.locked():
        raise AppError(409, "job_already_running", f"The {name} job is already running")
    return lock


@router.post("/feeds/sync", response_model=OperationResult)
async def sync_feeds(request: Request, _: AdminDep) -> OperationResult:
    _require_embedded_pipeline_control(request)
    lock = await _enter_job(request, "feeds")
    async with lock:
        service = IngestionService(
            request.app.state.database.session_factory, request.app.state.settings
        )
        return OperationResult(details=await service.sync_all())


@router.get("/feeds/status")
async def feed_status(session: SessionDep) -> list[dict[str, object]]:
    runs = list(
        (await session.scalars(select(FeedRun).order_by(FeedRun.started_at.desc()).limit(50))).all()
    )
    return [
        {
            "id": run.id,
            "feed": run.feed_name,
            "status": run.status.value,
            "started_at": run.started_at,
            "completed_at": run.completed_at,
            "received": run.received_count,
            "inserted": run.inserted_count,
            "updated": run.updated_count,
            "rejected": run.rejected_count,
            "duplicates_collapsed": max(
                0,
                run.received_count - run.inserted_count - run.updated_count - run.rejected_count,
            )
            if run.status is not FeedRunStatus.FAILED
            else 0,
            "error": run.error,
        }
        for run in runs
    ]


@router.post("/enrichment/run", response_model=OperationResult)
async def run_enrichment(request: Request, _: AdminDep) -> OperationResult:
    _require_embedded_pipeline_control(request)
    lock = await _enter_job(request, "enrichment")
    async with lock:
        service = EnrichmentService(
            request.app.state.database.session_factory, request.app.state.settings
        )
        return OperationResult(details=await service.enrich_pending())


@router.post("/analysis/run", response_model=OperationResult)
async def run_analysis(request: Request, _: AdminDep) -> OperationResult:
    _require_embedded_pipeline_control(request)
    lock = await _enter_job(request, "analysis")
    async with lock:
        return OperationResult(
            details=await PipelineService(
                request.app.state.database.session_factory,
                request.app.state.settings,
            ).run_analysis()
        )
