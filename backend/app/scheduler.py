from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.enrichment import EnrichmentService
from app.errors import AppError
from app.genai import ReportService, build_provider
from app.ingestion import IngestionService
from app.models import ReportCadence, ReportSchedule
from app.pipeline import PipelineService
from app.report_scheduling import ReportScheduleStore, calendar_report_period

logger = logging.getLogger(__name__)
REPORT_JOB_ID = "scheduled-report"


class SchedulerManager:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        locks: dict[str, asyncio.Lock],
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self.locks = locks
        self.scheduler = AsyncIOScheduler(timezone=UTC)
        self.startup_tasks: set[asyncio.Task[object]] = set()
        self.report_schedule_lock = asyncio.Lock()

    async def start(self) -> None:
        common = {"coalesce": True, "max_instances": 1, "misfire_grace_time": 900}
        self.scheduler.add_job(
            self.run_feeds,
            IntervalTrigger(hours=self.settings.feed_sync_hours),
            id="feed-sync",
            replace_existing=True,
            **common,
        )
        self.scheduler.add_job(
            self.run_enrichment,
            IntervalTrigger(minutes=self.settings.enrichment_interval_minutes),
            id="enrichment",
            replace_existing=True,
            **common,
        )
        self.scheduler.add_job(
            self.run_analysis,
            IntervalTrigger(hours=self.settings.analysis_interval_hours),
            id="analysis",
            replace_existing=True,
            **common,
        )
        schedule = await ReportScheduleStore(self.session_factory).get()
        self.configure_report_job(schedule.cadence)
        self.scheduler.start()
        if self.settings.run_jobs_on_startup:
            task = asyncio.create_task(self.run_startup_pipeline(), name="startup-pipeline")
            self.startup_tasks.add(task)
            task.add_done_callback(self.startup_tasks.discard)

    def configure_report_job(self, cadence: ReportCadence) -> None:
        if self.scheduler.get_job(REPORT_JOB_ID) is not None:
            self.scheduler.remove_job(REPORT_JOB_ID)
        trigger_options: dict[str, object] = {
            "hour": self.settings.report_hour_utc,
            "minute": 0,
            "timezone": UTC,
        }
        if cadence is ReportCadence.WEEKLY:
            trigger_options["day_of_week"] = self.settings.report_day_of_week
        else:
            trigger_options["day"] = 1
        self.scheduler.add_job(
            self.run_scheduled_report,
            CronTrigger(**trigger_options),
            id=REPORT_JOB_ID,
            kwargs={"cadence": cadence},
            replace_existing=True,
            coalesce=True,
            max_instances=1,
            misfire_grace_time=900,
        )

    def next_report_run(self) -> datetime | None:
        if not self.scheduler.running:
            return None
        job = self.scheduler.get_job(REPORT_JOB_ID)
        return job.next_run_time if job is not None else None

    async def update_report_schedule(self, cadence: ReportCadence) -> ReportSchedule:
        """Serialize cadence persistence and job replacement within this process."""

        async with self.report_schedule_lock:
            schedule = await ReportScheduleStore(self.session_factory).set(cadence)
            if self.scheduler.running:
                self.configure_report_job(schedule.cadence)
            return schedule

    async def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        for task in self.startup_tasks:
            task.cancel()
        if self.startup_tasks:
            await asyncio.gather(*self.startup_tasks, return_exceptions=True)

    async def run_startup_pipeline(self) -> None:
        await self.run_feeds()
        await self.run_enrichment()
        await self.run_analysis()

    async def run_feeds(self) -> None:
        async with self.locks["feeds"]:
            result = await IngestionService(self.session_factory, self.settings).sync_all()
            logger.info("Scheduled feed sync completed: %s", result)

    async def run_enrichment(self) -> None:
        async with self.locks["enrichment"]:
            result = await EnrichmentService(self.session_factory, self.settings).enrich_pending()
            logger.info("Scheduled enrichment completed: %s", result)

    async def run_analysis(self) -> None:
        async with self.locks["analysis"]:
            result = await PipelineService(self.session_factory, self.settings).run_analysis()
            logger.info("Scheduled analysis completed: %s", result)

    async def run_scheduled_report(self, cadence: ReportCadence) -> None:
        try:
            provider = build_provider(self.settings)
        except AppError as exc:
            logger.warning("Scheduled %s report skipped: %s", cadence.value, exc.message)
            return
        start, end = calendar_report_period(
            cadence,
            datetime.now(UTC),
            weekly_day=self.settings.report_day_of_week,
        )
        async with self.locks["reports"]:
            try:
                report = await ReportService(self.session_factory, provider).generate(
                    period_start=start,
                    period_end=end,
                    cadence=cadence,
                )
            except AppError as exc:
                if exc.code == "report_no_evidence":
                    logger.info(
                        "Scheduled %s report skipped because the completed period has no evidence",
                        cadence.value,
                    )
                    return
                raise
            logger.info("Scheduled report created: id=%s at=%s", report.id, datetime.now(UTC))
