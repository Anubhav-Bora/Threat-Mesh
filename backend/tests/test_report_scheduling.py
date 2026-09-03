from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.genai.providers import StaticProvider
from app.genai.reports import ReportService
from app.models import IOC, Report, ReportCadence, ReportSchedule
from app.report_scheduling import ReportScheduleStore, calendar_report_period
from app.scheduler import REPORT_JOB_ID
from tests.factories import make_ioc


def test_weekly_calendar_period_uses_last_complete_configured_week() -> None:
    start, end = calendar_report_period(
        ReportCadence.WEEKLY,
        datetime(2026, 8, 31, 6, 15, tzinfo=UTC),
        weekly_day="mon",
    )

    assert start == datetime(2026, 8, 24, tzinfo=UTC)
    assert end == datetime(2026, 8, 31, tzinfo=UTC)


def test_monthly_calendar_period_handles_year_rollover() -> None:
    start, end = calendar_report_period(
        ReportCadence.MONTHLY,
        datetime(2027, 1, 1, 6, tzinfo=UTC),
    )

    assert start == datetime(2026, 12, 1, tzinfo=UTC)
    assert end == datetime(2027, 1, 1, tzinfo=UTC)


@pytest.mark.asyncio
async def test_low_confidence_observations_are_not_labeled_high_confidence(app) -> None:
    indicator = make_ioc(value="9.9.9.9", confidence_score=69.9)
    async with app.state.database.session_factory() as session:
        session.add(indicator)
        await session.commit()
        now = datetime.now(UTC)
        facts = await ReportService.collect_facts(
            session,
            now - timedelta(days=365),
            now + timedelta(days=1),
        )

    assert facts["high_confidence_observations"] == 0
    assert facts["sample_high_confidence_observations"] == []


@pytest.mark.asyncio
async def test_report_schedule_api_is_public_to_read_and_admin_only_to_change(client, app) -> None:
    initial = await client.get("/api/v1/reports/schedule")

    assert initial.status_code == 200
    assert initial.json() == {
        "cadence": "weekly",
        "scheduler_running": False,
        "scheduler_mode": "disabled",
        "provider_configured": False,
        "next_run_at": None,
        "timezone": "UTC",
        "hour_utc": 6,
        "weekly_day": "mon",
        "monthly_day": 1,
        "updated_at": initial.json()["updated_at"],
        "admin_auth_required": True,
    }

    unauthorized = await client.put(
        "/api/v1/reports/schedule",
        json={"cadence": "monthly"},
        headers={"X-API-Key": "wrong"},
    )
    assert unauthorized.status_code == 401

    changed = await client.put(
        "/api/v1/reports/schedule",
        json={"cadence": "monthly"},
        headers={"X-API-Key": "test-admin-key"},
    )
    assert changed.status_code == 200
    assert changed.json()["cadence"] == "monthly"
    assert changed.json()["next_run_at"] is None

    persisted = await client.get("/api/v1/reports/schedule")
    assert persisted.json()["cadence"] == "monthly"
    async with app.state.database.session_factory() as session:
        schedule = await session.get(ReportSchedule, 1)
        assert schedule is not None and schedule.cadence is ReportCadence.MONTHLY


@pytest.mark.asyncio
async def test_report_schedule_rejects_unknown_cadence_and_manual_generation(client) -> None:
    invalid = await client.put(
        "/api/v1/reports/schedule",
        json={"cadence": "quarterly"},
        headers={"X-API-Key": "test-admin-key"},
    )
    manual = await client.post(
        "/api/v1/reports",
        json={},
        headers={"X-API-Key": "test-admin-key"},
    )

    assert invalid.status_code == 422
    assert manual.status_code == 405


@pytest.mark.asyncio
async def test_running_scheduler_update_installs_matching_job_and_next_run(client, app) -> None:
    manager = app.state.scheduler_manager
    app.state.settings.scheduler_enabled = True
    manager.scheduler.start(paused=True)

    changed = await client.put(
        "/api/v1/reports/schedule",
        json={"cadence": "monthly"},
        headers={"X-API-Key": "test-admin-key"},
    )

    assert changed.status_code == 200
    body = changed.json()
    assert body["scheduler_running"] is True
    assert body["scheduler_mode"] == "embedded"
    assert body["next_run_at"] is not None
    job = manager.scheduler.get_job(REPORT_JOB_ID)
    assert job is not None
    assert job.kwargs == {"cadence": ReportCadence.MONTHLY}
    assert datetime.fromisoformat(body["next_run_at"]) == job.next_run_time


@pytest.mark.asyncio
async def test_concurrent_schedule_updates_keep_storage_and_job_consistent(
    app, monkeypatch
) -> None:
    manager = app.state.scheduler_manager
    manager.scheduler.start(paused=True)
    original_set = ReportScheduleStore.set

    async def delayed_set(store: ReportScheduleStore, cadence: ReportCadence) -> ReportSchedule:
        schedule = await original_set(store, cadence)
        if cadence is ReportCadence.WEEKLY:
            await asyncio.sleep(0.02)
        return schedule

    monkeypatch.setattr(ReportScheduleStore, "set", delayed_set)
    weekly = asyncio.create_task(manager.update_report_schedule(ReportCadence.WEEKLY))
    await asyncio.sleep(0)
    monthly = asyncio.create_task(manager.update_report_schedule(ReportCadence.MONTHLY))
    await asyncio.gather(weekly, monthly)

    async with app.state.database.session_factory() as session:
        persisted = await session.get(ReportSchedule, 1)
    job = manager.scheduler.get_job(REPORT_JOB_ID)
    assert persisted is not None and persisted.cadence is ReportCadence.MONTHLY
    assert job is not None and job.kwargs == {"cadence": ReportCadence.MONTHLY}


@pytest.mark.asyncio
async def test_dynamic_report_trigger_switches_between_weekly_and_monthly(app) -> None:
    manager = app.state.scheduler_manager
    manager.configure_report_job(ReportCadence.MONTHLY)
    monthly_job = manager.scheduler.get_job(REPORT_JOB_ID)
    assert monthly_job is not None
    assert monthly_job.trigger.get_next_fire_time(
        None, datetime(2026, 8, 28, tzinfo=UTC)
    ) == datetime(2026, 9, 1, 6, tzinfo=UTC)

    manager.configure_report_job(ReportCadence.WEEKLY)
    weekly_job = manager.scheduler.get_job(REPORT_JOB_ID)
    assert weekly_job is not None
    assert weekly_job.trigger.get_next_fire_time(
        None, datetime(2026, 8, 28, tzinfo=UTC)
    ) == datetime(2026, 8, 31, 6, tzinfo=UTC)


@pytest.mark.asyncio
async def test_scheduled_no_evidence_period_is_a_normal_skip(app, monkeypatch) -> None:
    provider = StaticProvider("This response must not be requested.")
    monkeypatch.setattr("app.scheduler.build_provider", lambda _settings: provider)

    await app.state.scheduler_manager.run_scheduled_report(ReportCadence.WEEKLY)

    assert provider.prompts == []
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(Report.id))) == 0


@pytest.mark.asyncio
async def test_monthly_report_records_cadence_and_calendar_title(app) -> None:
    indicator = make_ioc(value="8.8.8.8")
    indicator.first_seen = datetime(2026, 7, 10, tzinfo=UTC)
    indicator.last_seen = datetime(2026, 7, 20, tzinfo=UTC)
    async with app.state.database.session_factory() as session:
        session.add(indicator)
        await session.commit()

    report = await ReportService(
        app.state.database.session_factory,
        StaticProvider("Grounded monthly report."),
    ).generate(
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 8, 1, tzinfo=UTC),
        cadence=ReportCadence.MONTHLY,
    )

    assert report.cadence is ReportCadence.MONTHLY
    assert report.title == "ThreatMesh Monthly CTI Report — 2026-08-01"
    assert report.facts_json["report_cadence"] == "monthly"
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(IOC.id))) == 1


@pytest.mark.asyncio
async def test_scheduled_report_generation_is_idempotent_for_period_and_provenance(app) -> None:
    indicator = make_ioc(value="1.1.1.1")
    indicator.first_seen = datetime(2026, 8, 24, tzinfo=UTC)
    indicator.last_seen = datetime(2026, 8, 30, tzinfo=UTC)
    async with app.state.database.session_factory() as session:
        session.add(indicator)
        await session.commit()

    provider = StaticProvider("Grounded weekly report.")
    service = ReportService(app.state.database.session_factory, provider)
    arguments = {
        "period_start": datetime(2026, 8, 24, tzinfo=UTC),
        "period_end": datetime(2026, 8, 31, tzinfo=UTC),
        "cadence": ReportCadence.WEEKLY,
    }
    first = await service.generate(**arguments)
    second = await service.generate(**arguments)

    assert second.id == first.id
    assert len(provider.prompts) == 1
    assert first.schedule_key is not None and first.schedule_key.endswith(":live")
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(Report.id))) == 1


@pytest.mark.asyncio
async def test_external_scheduler_reports_next_run_without_embedded_process(client, app) -> None:
    app.state.settings.external_scheduler_enabled = True

    response = await client.get("/api/v1/reports/schedule")

    assert response.status_code == 200
    body = response.json()
    assert body["scheduler_running"] is True
    assert body["scheduler_mode"] == "external"
    assert body["next_run_at"] is not None
    assert app.state.scheduler_manager.scheduler.running is False
