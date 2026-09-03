from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select

from app.genai.providers import StaticProvider
from app.jobs import _generate_due_report, run_coordinator
from app.models import Report
from tests.factories import make_ioc


class MondayBeforeReportHour(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        value = cls(2026, 8, 31, 3, tzinfo=UTC)
        return value if tz is None else value.astimezone(tz)


class MondayAtReportHour(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001
        value = cls(2026, 8, 31, 6, tzinfo=UTC)
        return value if tz is None else value.astimezone(tz)


@pytest.mark.asyncio
async def test_external_report_waits_for_hour_and_is_idempotent(app, settings, monkeypatch) -> None:
    previous = make_ioc(value="1.1.1.1")
    previous.first_seen = datetime(2026, 8, 17, tzinfo=UTC)
    previous.last_seen = datetime(2026, 8, 23, tzinfo=UTC)
    current = make_ioc(value="8.8.8.8")
    current.first_seen = datetime(2026, 8, 24, tzinfo=UTC)
    current.last_seen = datetime(2026, 8, 30, tzinfo=UTC)
    async with app.state.database.session_factory() as session:
        session.add_all([previous, current])
        await session.commit()

    provider = StaticProvider("Grounded scheduled report.")
    monkeypatch.setattr("app.jobs.build_provider", lambda _settings: provider)
    monkeypatch.setattr("app.jobs.datetime", MondayBeforeReportHour)
    before = await _generate_due_report(app.state.database, settings)

    monkeypatch.setattr("app.jobs.datetime", MondayAtReportHour)
    at_boundary = await _generate_due_report(app.state.database, settings)
    repeated = await _generate_due_report(app.state.database, settings)

    assert before["status"] == "created"
    assert at_boundary["status"] == "created"
    assert repeated == {
        "status": "current",
        "report_id": at_boundary["report_id"],
        "cadence": "weekly",
    }
    assert len(provider.prompts) == 2
    async with app.state.database.session_factory() as session:
        reports = list((await session.scalars(select(Report).order_by(Report.period_end))).all())
    assert [report.period_end.date().isoformat() for report in reports] == [
        "2026-08-24",
        "2026-08-31",
    ]


@pytest.mark.asyncio
async def test_coordinator_uses_shared_pipeline_and_report_stage(settings, monkeypatch) -> None:
    pipeline_result = {"feeds": {"succeeded": 3}, "analysis": {"confidence": {"updated": 4}}}
    pipeline = AsyncMock(return_value=pipeline_result)
    report = AsyncMock(return_value={"status": "skipped", "reason": "report_no_evidence"})
    monkeypatch.setattr("app.jobs.PipelineService.run_full", pipeline)
    monkeypatch.setattr("app.jobs._generate_due_report", report)

    result = await run_coordinator(settings)

    assert result == {
        "status": "completed",
        "pipeline": pipeline_result,
        "report": {"status": "skipped", "reason": "report_no_evidence"},
    }
    pipeline.assert_awaited_once()
    report.assert_awaited_once()
