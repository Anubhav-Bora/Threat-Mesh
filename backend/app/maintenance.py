from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import Campaign, FeedRun, GeoCache, IOC, Report


def _utc(value: datetime | None = None) -> datetime:
    current = value or datetime.now(UTC)
    return current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)


class DataRetentionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        retention_days: int,
    ) -> None:
        self.session_factory = session_factory
        self.retention_days = retention_days

    async def purge_stale_records(self, now: datetime | None = None) -> dict[str, int]:
        if self.retention_days <= 0:
            return {
                "feeds": 0,
                "geocache": 0,
                "iocs": 0,
                "campaigns": 0,
                "reports": 0,
            }

        cutoff = _utc(now) - timedelta(days=self.retention_days)
        async with self.session_factory() as session:
            deleted_reports = (
                await session.execute(delete(Report).where(Report.created_at < cutoff))
            ).rowcount
            deleted_iocs = (
                await session.execute(delete(IOC).where(IOC.last_seen < cutoff))
            ).rowcount
            active_campaign = (
                select(IOC.id)
                .where(IOC.cluster_id == Campaign.id, IOC.last_seen >= cutoff)
                .correlate(Campaign)
                .exists()
            )
            stale_campaigns = delete(Campaign).where(
                Campaign.last_seen < cutoff,
                ~active_campaign,
            )
            deleted_campaigns = (await session.execute(stale_campaigns)).rowcount
            deleted_geo_cache = (
                await session.execute(delete(GeoCache).where(GeoCache.fetched_at < cutoff))
            ).rowcount
            deleted_feed_runs = (
                await session.execute(delete(FeedRun).where(FeedRun.started_at < cutoff))
            ).rowcount
            await session.commit()

        return {
            "feeds": int(deleted_feed_runs or 0),
            "geocache": int(deleted_geo_cache or 0),
            "iocs": int(deleted_iocs or 0),
            "campaigns": int(deleted_campaigns or 0),
            "reports": int(deleted_reports or 0),
        }
