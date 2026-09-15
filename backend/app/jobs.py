from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from app.config import Settings
from app.database import Database
from app.errors import AppError
from app.genai import ReportService, build_provider
from app.genai.reports import report_schedule_key
from app.logging import configure_logging
from app.maintenance import DataRetentionService
from app.models import Report
from app.pipeline import PipelineService
from app.report_scheduling import ReportScheduleStore, calendar_report_period

logger = logging.getLogger(__name__)
COORDINATOR_LOCK_ID = 846_736_841


@asynccontextmanager
async def _coordinator_lock(database: Database) -> AsyncIterator[bool]:
    """Hold a deployment-wide advisory lock for PostgreSQL job executions."""

    if database.engine.dialect.name != "postgresql":
        yield True
        return
    async with database.engine.connect() as connection:
        acquired = bool(
            await connection.scalar(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": COORDINATOR_LOCK_ID},
            )
        )
        try:
            yield acquired
        finally:
            if acquired:
                await connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": COORDINATOR_LOCK_ID},
                )


async def _generate_due_report(database: Database, settings: Settings) -> dict[str, object]:
    schedule = await ReportScheduleStore(database.session_factory).get()
    reference = datetime.now(UTC)
    # Before today's configured generation hour, the boundary that became due
    # today still belongs to the previous scheduler cycle.
    if reference.hour < settings.report_hour_utc:
        reference -= timedelta(days=1)
    start, end = calendar_report_period(
        schedule.cadence,
        reference,
        weekly_day=settings.report_day_of_week,
    )
    async with database.session_factory() as session:
        facts = await ReportService.collect_facts(session, start, end)
        if facts["analysis_scope"] == "none":
            return {
                "status": "skipped",
                "reason": "report_no_evidence",
                "cadence": schedule.cadence.value,
            }
        schedule_key = report_schedule_key(
            schedule.cadence,
            start,
            end,
            is_demo=facts["analysis_scope"] == "demo",
        )
        existing = await session.scalar(select(Report).where(Report.schedule_key == schedule_key))
    if existing is not None:
        return {
            "status": "current",
            "report_id": existing.id,
            "cadence": schedule.cadence.value,
        }
    try:
        provider = build_provider(settings)
        report = await ReportService(database.session_factory, provider).generate(
            period_start=start,
            period_end=end,
            cadence=schedule.cadence,
        )
    except AppError as exc:
        if exc.code in {"report_no_evidence", "llm_disabled"}:
            return {
                "status": "skipped",
                "reason": exc.code,
                "cadence": schedule.cadence.value,
            }
        raise
    return {
        "status": "created",
        "report_id": report.id,
        "cadence": schedule.cadence.value,
    }


async def run_coordinator(settings: Settings | None = None) -> dict[str, object]:
    resolved = settings or Settings()
    configure_logging(resolved.log_level, json_logs=resolved.is_production)
    database = Database(resolved)
    try:
        if resolved.auto_create_schema:
            await database.create_schema()
        async with _coordinator_lock(database) as acquired:
            if not acquired:
                result: dict[str, object] = {
                    "status": "skipped",
                    "reason": "already_running",
                }
            else:
                await DataRetentionService(
                    database.session_factory,
                    resolved.data_retention_days,
                ).purge_stale_records(datetime.now(UTC))
                pipeline = await PipelineService(database.session_factory, resolved).run_full()
                report = await _generate_due_report(database, resolved)
                result = {"status": "completed", "pipeline": pipeline, "report": report}
            logger.info("Coordinator finished: %s", result)
            return result
    finally:
        await database.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatMesh external jobs")
    parser.add_argument("command", choices=["coordinator"])
    args = parser.parse_args()
    if args.command == "coordinator":
        asyncio.run(run_coordinator())


if __name__ == "__main__":
    main()
