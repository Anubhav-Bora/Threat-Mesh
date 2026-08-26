from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from app.api.dependencies import AdminDep, AIRateLimitDep, SessionDep
from app.api.schemas import GenerateReportRequest, ReportDetail, ReportSummary
from app.errors import AppError
from app.genai import ReportService, build_provider
from app.models import Report

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[ReportSummary])
async def list_reports(session: SessionDep) -> list[ReportSummary]:
    reports = list(
        (await session.scalars(select(Report).order_by(Report.created_at.desc()).limit(100))).all()
    )
    return [ReportSummary.model_validate(report) for report in reports]


@router.post("", response_model=ReportDetail, status_code=201)
async def generate_report(
    body: GenerateReportRequest,
    request: Request,
    _: AdminDep,
    __: AIRateLimitDep,
) -> ReportDetail:
    provider = getattr(request.app.state, "llm_provider_override", None) or build_provider(
        request.app.state.settings
    )
    service = ReportService(request.app.state.database.session_factory, provider)
    report = await service.generate(period_start=body.period_start, period_end=body.period_end)
    return ReportDetail.model_validate(report)


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
