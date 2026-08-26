from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.ingestion.base import FeedBatch, FeedConnector, NormalizedIOC, indicator_key
from app.ingestion.feodo import FeodoConnector
from app.ingestion.threatfox import ThreatFoxConnector
from app.ingestion.urlhaus import URLhausConnector
from app.models import IOC, FeedRun, FeedRunStatus

logger = logging.getLogger(__name__)


@dataclass
class FeedSyncResult:
    feed: str
    status: FeedRunStatus | None = None
    received: int = 0
    inserted: int = 0
    updated: int = 0
    rejected: int = 0
    skipped: bool = False
    error: str | None = None


class IngestionService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        connectors: list[FeedConnector] | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self._client = client
        self._connectors = connectors

    def build_connectors(self, client: httpx.AsyncClient) -> list[FeedConnector]:
        return [
            URLhausConnector(
                client,
                self.settings.urlhaus_url,
                auth_key=self.settings.abusech_auth_key,
                max_response_bytes=self.settings.feed_max_response_bytes,
            ),
            ThreatFoxConnector(
                client,
                self.settings.threatfox_url,
                auth_key=self.settings.abusech_auth_key,
                max_response_bytes=self.settings.feed_max_response_bytes,
            ),
            FeodoConnector(
                client,
                self.settings.feodo_url,
                max_response_bytes=self.settings.feed_max_response_bytes,
            ),
        ]

    async def sync_all(self) -> dict[str, object]:
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": self.settings.http_user_agent, "Accept": "application/json"},
        )
        results: list[FeedSyncResult] = []
        try:
            for connector in self._connectors or self.build_connectors(client):
                if connector.requires_auth and not connector.auth_key:
                    results.append(
                        FeedSyncResult(
                            feed=connector.name,
                            skipped=True,
                            error=(
                                "ABUSECH_AUTH_KEY is not configured; obtain a free key from "
                                "https://auth.abuse.ch/"
                            ),
                        )
                    )
                    continue
                results.append(await self.sync_feed(connector))
        finally:
            if owns_client:
                await client.aclose()
        return {
            "feeds": [asdict(result) for result in results],
            "inserted": sum(result.inserted for result in results),
            "updated": sum(result.updated for result in results),
            "failed": sum(1 for result in results if result.status is FeedRunStatus.FAILED),
            "skipped": sum(1 for result in results if result.skipped),
        }

    async def sync_feed(self, connector: FeedConnector) -> FeedSyncResult:
        result = FeedSyncResult(feed=connector.name)
        async with self.session_factory() as session:
            run = FeedRun(feed_name=connector.name, status=FeedRunStatus.RUNNING)
            session.add(run)
            await session.commit()
            await session.refresh(run)
            run_id = run.id
            try:
                fetched = await connector.fetch()
                batch = (
                    fetched
                    if isinstance(fetched, FeedBatch)
                    else FeedBatch(indicators=fetched, attempted=len(fetched), rejected=0)
                )
                indicators = batch.indicators
                result.received = batch.attempted
                result.rejected = batch.rejected
                unique_indicators: dict[tuple[object, str, str], NormalizedIOC] = {}
                for indicator in indicators:
                    key = (
                        indicator.ioc_type,
                        indicator_key(indicator.ioc_value, indicator.ioc_type, indicator.port),
                        indicator.source_feed,
                    )
                    previous = unique_indicators.get(key)
                    if previous is None or indicator.last_seen >= previous.last_seen:
                        unique_indicators[key] = indicator
                result.rejected += len(indicators) - len(unique_indicators)
                for indicator in unique_indicators.values():
                    inserted = await self._upsert(session, indicator)
                    if inserted:
                        result.inserted += 1
                    else:
                        result.updated += 1
                if result.received > 0 and not unique_indicators:
                    result.status = FeedRunStatus.FAILED
                    result.error = (
                        f"all {result.received} received records were rejected during normalization"
                    )
                elif result.rejected:
                    result.status = FeedRunStatus.PARTIAL
                    result.error = (
                        f"{result.rejected} of {result.received} received records were rejected"
                    )
                else:
                    result.status = FeedRunStatus.SUCCEEDED
                run.status = result.status
                run.received_count = result.received
                run.inserted_count = result.inserted
                run.updated_count = result.updated
                run.rejected_count = result.rejected
                run.error = result.error
            except Exception as exc:
                await session.rollback()
                result.error = str(exc)[:1000]
                logger.exception("Feed sync failed", extra={"feed": connector.name})
                run = await session.get(FeedRun, run_id)
                if run is None:
                    run = FeedRun(feed_name=connector.name, status=FeedRunStatus.FAILED)
                    session.add(run)
                run.status = FeedRunStatus.FAILED
                result.status = FeedRunStatus.FAILED
                run.error = result.error
            finally:
                run.completed_at = datetime.now(UTC)
                await session.commit()
        return result

    @staticmethod
    async def _upsert(session: AsyncSession, indicator: NormalizedIOC) -> bool:
        existing = await session.scalar(
            select(IOC).where(
                IOC.ioc_type == indicator.ioc_type,
                IOC.indicator_key
                == indicator_key(indicator.ioc_value, indicator.ioc_type, indicator.port),
                IOC.source_feed == indicator.source_feed,
            )
        )
        if existing is None:
            session.add(
                IOC(
                    ioc_value=indicator.ioc_value,
                    indicator_key=indicator_key(
                        indicator.ioc_value, indicator.ioc_type, indicator.port
                    ),
                    ioc_type=indicator.ioc_type,
                    port=indicator.port,
                    malware_family=indicator.malware_family,
                    first_seen=indicator.first_seen,
                    last_seen=indicator.last_seen,
                    source_feed=indicator.source_feed,
                    is_demo=False,
                    confidence_score=indicator.confidence_hint,
                    raw_json=indicator.raw_json,
                )
            )
            return True
        existing.first_seen = min(_as_utc(existing.first_seen), _as_utc(indicator.first_seen))
        existing.last_seen = max(_as_utc(existing.last_seen), _as_utc(indicator.last_seen))
        existing.malware_family = indicator.malware_family or existing.malware_family
        existing.ioc_type = indicator.ioc_type
        existing.port = indicator.port
        existing.is_demo = False
        existing.raw_json = indicator.raw_json
        existing.confidence_score = max(existing.confidence_score, indicator.confidence_hint)
        return False


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
