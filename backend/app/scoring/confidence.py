from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import IOC

SOURCE_REPUTATION = {
    "feodo": 0.95,
    "threatfox": 0.90,
    "urlhaus": 0.88,
    "phishtank": 0.85,
}
CONFIDENCE_MODEL_VERSION = "heuristic-v1"


@dataclass(frozen=True, slots=True)
class ConfidenceComponent:
    key: str
    label: str
    score: float
    max_score: float
    evidence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "score": self.score,
            "max_score": self.max_score,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class ConfidenceBreakdown:
    total: float
    formula_version: str
    calculated_at: datetime
    components: tuple[ConfidenceComponent, ...]


def confidence_breakdown(
    ioc: IOC,
    *,
    corroborating_feeds: int,
    now: datetime | None = None,
) -> ConfidenceBreakdown:
    """Return the complete, reproducible confidence snapshot for one observation."""

    current = now or datetime.now(UTC)
    current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
    last_seen = ioc.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    else:
        last_seen = last_seen.astimezone(UTC)
    age_days = max(0.0, (current - last_seen).total_seconds() / 86_400)
    reputation = SOURCE_REPUTATION.get(ioc.source_feed.lower(), 0.65)
    source_points = round(40.0 * reputation, 1)
    feed_count = max(1, corroborating_feeds)
    corroboration_points = round(min(20.0, (feed_count - 1) * 10.0), 1)
    recency_points = round(30.0 * math.exp(-age_days / 30.0), 1)
    context_signals = [
        ("malware family", 4.0, bool(ioc.malware_family)),
        ("ASN", 3.0, bool(ioc.asn)),
        ("ATT&CK context", 3.0, bool(ioc.attack_technique_ids)),
    ]
    context_points = sum(points for _, points, present in context_signals if present)
    present_context = [label for label, _, present in context_signals if present]
    components = (
        ConfidenceComponent(
            key="source_reputation",
            label="Source reputation",
            score=source_points,
            max_score=40.0,
            evidence=f"{ioc.source_feed} reputation weight {reputation:.2f}",
        ),
        ConfidenceComponent(
            key="corroboration",
            label="Independent corroboration",
            score=corroboration_points,
            max_score=20.0,
            evidence=(
                f"{feed_count} provenance-isolated source feed{'s' if feed_count != 1 else ''}"
            ),
        ),
        ConfidenceComponent(
            key="recency",
            label="Observation recency",
            score=recency_points,
            max_score=30.0,
            evidence=f"{age_days:.1f} days old when scored",
        ),
        ConfidenceComponent(
            key="context",
            label="Analytic context",
            score=round(context_points, 1),
            max_score=10.0,
            evidence=(", ".join(present_context) if present_context else "No enrichment context"),
        ),
    )
    return ConfidenceBreakdown(
        total=round(min(100.0, sum(component.score for component in components)), 1),
        formula_version=CONFIDENCE_MODEL_VERSION,
        calculated_at=current,
        components=components,
    )


def confidence_score(
    ioc: IOC,
    *,
    corroborating_feeds: int,
    now: datetime | None = None,
) -> float:
    """Score from source quality, corroboration, recency, and available context."""

    return confidence_breakdown(ioc, corroborating_feeds=corroborating_feeds, now=now).total


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
            scored_at = datetime.now(UTC)
            for ioc in indicators:
                feeds = len(sources_by_indicator[(ioc.is_demo, ioc.ioc_type, ioc.indicator_key)])
                feed_counts[feeds] += 1
                breakdown = confidence_breakdown(
                    ioc,
                    corroborating_feeds=feeds,
                    now=scored_at,
                )
                ioc.confidence_score = breakdown.total
                ioc.confidence_model_version = breakdown.formula_version
                ioc.confidence_scored_at = breakdown.calculated_at
                ioc.confidence_components = [
                    component.as_dict() for component in breakdown.components
                ]
                total += ioc.confidence_score
            await session.commit()
        return {
            "updated": len(indicators),
            "average_score": round(total / len(indicators), 1) if indicators else 0.0,
            "corroborated": sum(count for feeds, count in feed_counts.items() if feeds > 1),
        }
