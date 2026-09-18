from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from app.api.dependencies import AdminDep, AIRateLimitDep, SessionDep
from app.api.schemas import (
    ReportDetail,
    ReportScheduleResponse,
    ReportSummary,
    UpdateReportScheduleRequest,
)
from app.errors import AppError
from app.genai import ReportService, build_provider, provider_is_configured
from app.maintenance import DataRetentionService
from app.models import Report, ReportSchedule
from app.models.enums import ReportCadence
from app.report_scheduling import ReportScheduleStore, calendar_report_period, next_report_run

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportSummary])
async def list_reports(session: SessionDep, response: Response) -> list[ReportSummary]:
    response.headers["Cache-Control"] = "no-store"
    reports = list(
        (await session.scalars(select(Report).order_by(Report.created_at.desc()).limit(100))).all()
    )
    return [ReportSummary.model_validate(report) for report in reports]


def _provider_configured(request: Request) -> bool:
    settings = request.app.state.settings
    return provider_is_configured(settings.llm_provider, settings) or provider_is_configured(
        settings.llm_fallback_provider, settings
    )


def _schedule_response(request: Request, schedule: ReportSchedule) -> ReportScheduleResponse:
    settings = request.app.state.settings
    manager = request.app.state.scheduler_manager
    embedded_running = bool(settings.scheduler_enabled and manager.scheduler.running)
    scheduler_mode = (
        "embedded"
        if embedded_running
        else "external"
        if settings.external_scheduler_enabled
        else "disabled"
    )
    scheduler_running = scheduler_mode != "disabled"
    next_run_at = (
        manager.next_report_run()
        if embedded_running
        else next_report_run(
            schedule.cadence,
            datetime.now(UTC),
            weekly_day=settings.report_day_of_week,
            hour_utc=settings.report_hour_utc,
        )
        if settings.external_scheduler_enabled
        else None
    )
    return ReportScheduleResponse(
        cadence=schedule.cadence,
        scheduler_running=scheduler_running,
        scheduler_mode=scheduler_mode,
        provider_configured=_provider_configured(request),
        next_run_at=next_run_at,
        hour_utc=settings.report_hour_utc,
        weekly_day=settings.report_day_of_week,
        updated_at=schedule.updated_at,
        admin_auth_required=settings.is_production or bool(settings.admin_api_key),
    )


@router.post("/generate", response_model=ReportDetail)
async def generate_report(request: Request, _: AIRateLimitDep) -> ReportDetail:
    settings = request.app.state.settings
    now = datetime.now(UTC)
    await DataRetentionService(
        request.app.state.database.session_factory,
        settings.data_retention_days,
    ).purge_stale_records(now)
    provider = build_provider(settings)
    start, end = calendar_report_period(
        ReportCadence.WEEKLY,
        now,
        weekly_day=settings.report_day_of_week,
    )
    async with request.app.state.job_locks["reports"]:
        report = await ReportService(request.app.state.database.session_factory, provider).generate(
            period_start=start,
            period_end=end,
            cadence=ReportCadence.WEEKLY,
            # A person explicitly requested this snapshot. Keep each on-demand
            # result, while scheduled jobs remain idempotent per reporting period.
            idempotent=False,
        )
    return ReportDetail.model_validate(report)


@router.get("/schedule", response_model=ReportScheduleResponse)
async def get_report_schedule(request: Request) -> ReportScheduleResponse:
    store = ReportScheduleStore(request.app.state.database.session_factory)
    return _schedule_response(request, await store.get())


@router.put("/schedule", response_model=ReportScheduleResponse)
async def update_report_schedule(
    body: UpdateReportScheduleRequest,
    request: Request,
    _: AdminDep,
) -> ReportScheduleResponse:
    manager = request.app.state.scheduler_manager
    schedule = await manager.update_report_schedule(body.cadence)
    return _schedule_response(request, schedule)


@router.get("/{report_id}", response_model=ReportDetail)
async def get_report(report_id: int, session: SessionDep, response: Response) -> ReportDetail:
    response.headers["Cache-Control"] = "no-store"
    report = await session.get(Report, report_id)
    if report is None:
        raise AppError(404, "report_not_found", f"Report {report_id} was not found")
    return ReportDetail.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(report_id: int, session: SessionDep) -> Response:
    report = await session.get(Report, report_id)
    if report is None:
        raise AppError(404, "report_not_found", f"Report {report_id} was not found")
    provenance = (
        "SYNTHETIC DEMO ONLY — not live threat intelligence."
        if report.is_demo
        else "Live-corpus analysis."
    )
    return Response(
        content=(f"# {report.title}\n\n> Provenance: {provenance}\n\n{report.report_text}\n"),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="threatmesh-report-{report.id}.md"'},
    )
