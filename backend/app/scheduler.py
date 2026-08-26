from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.attack_mapping import AttackMappingService
from app.clustering import ClusteringService
from app.config import Settings
from app.detection_rules import DetectionRuleService
from app.enrichment import EnrichmentService
from app.errors import AppError
from app.genai import ReportService, build_provider
from app.ingestion import IngestionService
from app.scoring import ConfidenceService

logger = logging.getLogger(__name__)


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

    def start(self) -> None:
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
        self.scheduler.add_job(
            self.run_weekly_report,
            CronTrigger(
                day_of_week=self.settings.report_day_of_week,
                hour=self.settings.report_hour_utc,
                minute=0,
                timezone=UTC,
            ),
            id="weekly-report",
            replace_existing=True,
            **common,
        )
        self.scheduler.start()
        if self.settings.run_jobs_on_startup:
            task = asyncio.create_task(self.run_startup_pipeline(), name="startup-pipeline")
            self.startup_tasks.add(task)
            task.add_done_callback(self.startup_tasks.discard)

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
            mapping = await AttackMappingService(self.session_factory).map_indicators()
            scores = await ConfidenceService(self.session_factory).recalculate()
            clusters = await ClusteringService(self.session_factory, self.settings).rebuild()
            rules = await DetectionRuleService(self.session_factory).generate(
                minimum_confidence=self.settings.minimum_rule_confidence,
                limit=1000,
            )
            logger.info(
                "Scheduled analysis completed: %s",
                {"mapping": mapping, "scores": scores, "clusters": clusters, "rules": rules},
            )

    async def run_weekly_report(self) -> None:
        try:
            provider = build_provider(self.settings)
        except AppError as exc:
            logger.warning("Weekly report skipped: %s", exc.message)
            return
        async with self.locks["reports"]:
            report = await ReportService(self.session_factory, provider).generate()
            logger.info("Scheduled report created: id=%s at=%s", report.id, datetime.now(UTC))
