from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from app.api.dependencies import AdminDep, SessionDep
from app.api.schemas import (
    ReportDetail,
    ReportScheduleResponse,
    ReportSummary,
    UpdateReportScheduleRequest,
)
from app.errors import AppError
from app.models import Report, ReportSchedule
from app.report_scheduling import ReportScheduleStore

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportSummary])
async def list_reports(session: SessionDep) -> list[ReportSummary]:
    reports = list(
        (await session.scalars(select(Report).order_by(Report.created_at.desc()).limit(100))).all()
    )
    return [ReportSummary.model_validate(report) for report in reports]


def _provider_configured(request: Request) -> bool:
    settings = request.app.state.settings
    provider = settings.llm_provider.lower()
    return provider == "ollama" or (provider == "gemini" and bool(settings.gemini_api_key))


def _schedule_response(request: Request, schedule: ReportSchedule) -> ReportScheduleResponse:
    settings = request.app.state.settings
    manager = request.app.state.scheduler_manager
    scheduler_running = bool(settings.scheduler_enabled and manager.scheduler.running)
    return ReportScheduleResponse(
        cadence=schedule.cadence,
        scheduler_running=scheduler_running,
        provider_configured=_provider_configured(request),
        next_run_at=manager.next_report_run() if scheduler_running else None,
        hour_utc=settings.report_hour_utc,
        weekly_day=settings.report_day_of_week,
        updated_at=schedule.updated_at,
        admin_auth_required=settings.is_production or bool(settings.admin_api_key),
    )


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
async def get_report(report_id: int, session: SessionDep) -> ReportDetail:
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
