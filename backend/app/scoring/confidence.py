from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import IOC

SOURCE_REPUTATION = {
    "feodo": 0.95,
    "threatfox": 0.90,
    "urlhaus": 0.88,
    "phishtank": 0.85,
}


def confidence_score(
    ioc: IOC,
    *,
    corroborating_feeds: int,
    now: datetime | None = None,
) -> float:
    """Score from source quality, corroboration, recency, and available context."""

    current = now or datetime.now(UTC)
    last_seen = ioc.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age_days = max(0.0, (current - last_seen).total_seconds() / 86_400)
    reputation = SOURCE_REPUTATION.get(ioc.source_feed.lower(), 0.65)
    source_points = 40.0 * reputation
    corroboration_points = min(20.0, max(0, corroborating_feeds - 1) * 10.0)
    recency_points = 30.0 * math.exp(-age_days / 30.0)
    context_points = 0.0
    context_points += 4.0 if ioc.malware_family else 0.0
    context_points += 3.0 if ioc.asn else 0.0
    context_points += 3.0 if ioc.attack_technique_ids else 0.0
    return round(
        min(100.0, source_points + corroboration_points + recency_points + context_points), 1
    )


class ConfidenceService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def recalculate(self) -> dict[str, int | float]:
        async with self.session_factory() as session:
            indicators = list((await session.scalars(select(IOC))).all())
            feed_counts = Counter()
            sources_by_indicator: dict[tuple[bool, object, str], set[str]] = {}
            for ioc in indicators:
                identity = (ioc.is_demo, ioc.ioc_type, ioc.indicator_key)
                sources_by_indicator.setdefault(identity, set()).add(ioc.source_feed)
            total = 0.0
            for ioc in indicators:
                feeds = len(sources_by_indicator[(ioc.is_demo, ioc.ioc_type, ioc.indicator_key)])
                feed_counts[feeds] += 1
                ioc.confidence_score = confidence_score(ioc, corroborating_feeds=feeds)
                total += ioc.confidence_score
            await session.commit()
        return {
            "updated": len(indicators),
            "average_score": round(total / len(indicators), 1) if indicators else 0.0,
            "corroborated": sum(count for feeds, count in feed_counts.items() if feeds > 1),
        }
