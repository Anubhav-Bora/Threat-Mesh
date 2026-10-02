from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models import IOC

# ---------------------------------------------------------------------------
# Source reputation table
# ---------------------------------------------------------------------------
# Weights are analyst-assigned estimates of feed curation quality on [0, 1].
# Feodo / ThreatFox: actively maintained C2 blocklists with editorial review.
# URLhaus: community-submitted with abuse.ch moderator review.
# Unknown feeds default to 0.65 (cautious, not zero — unknown ≠ wrong).
# ---------------------------------------------------------------------------
SOURCE_REPUTATION = {
    "feodo": 0.95,
    "threatfox": 0.90,
    "urlhaus": 0.88,
    "phishtank": 0.85,
}
_DEFAULT_REPUTATION: float = 0.65

# Increment this string whenever the formula changes so persisted snapshots
# remain attributable to the exact calculation that produced them.
CONFIDENCE_MODEL_VERSION = "heuristic-v2"

# ---------------------------------------------------------------------------
# Formula weight constants — heuristic-v2
# ---------------------------------------------------------------------------
# Total budget: 100 points across four components.
#
# 1. COMBINED ACTIVITY  (max 45 pts)
#    Replaces the old separate "source reputation" + "recency" components.
#    Motivation: a high-reputation feed entry that is 90 days old is not as
#    useful as a medium-reputation entry seen today.  Multiplying the two
#    signals forces them to reinforce each other rather than compensate.
#
#    activity = reputation × recency_factor
#    recency_factor = exp(-age_days / RECENCY_HALF_LIFE_DAYS)   ∈ (0, 1]
#    combined_points = MAX_ACTIVITY_POINTS × activity
#
#    Worked examples (rounded):
#      feodo,  age=0d   → 0.95 × 1.000 × 45 ≈ 42.8 pts
#      feodo,  age=30d  → 0.95 × 0.368 × 45 ≈ 15.7 pts
#      urlhaus,age=0d   → 0.88 × 1.000 × 45 ≈ 39.6 pts
#      urlhaus,age=60d  → 0.88 × 0.135 × 45 ≈  5.4 pts
#      unknown,age=7d   → 0.65 × 0.794 × 45 ≈ 23.2 pts
#
#    Half-life of 30 days reflects abuse.ch feed refresh cadence.
#
# 2. INDEPENDENT CORROBORATION  (max 20 pts)
#    Logarithmic growth: first additional source is worth the most; further
#    sources add diminishing value (mirrors real intelligence value of n-th
#    confirmation). Formula:
#      corroboration_points = MAX_CORROBORATION_POINTS
#                             × log(feed_count) / log(MAX_CORROBORATION_FEEDS)
#    where MAX_CORROBORATION_FEEDS = 4 (three independent sources is
#    considered "fully corroborated" for this feed set).
#    1 feed → 0 pts, 2 feeds → 10 pts, 3 feeds → 15.9 pts, 4+ → 20 pts.
#
# 3. FEED CONFIDENCE HINT  (max 10 pts)
#    Feed-provided confidence hints (e.g. ThreatFox confidence 0–100) were
#    previously stored but never scored. Now incorporated as a proportional
#    bonus: hint_points = MAX_HINT_POINTS × (hint / 100).
#    Falls back to 0 if no hint was provided.
#    This component is bounded small enough that it cannot override a strong
#    combined-activity signal, but it does differentiate within a feed.
#
# 4. ANALYTIC CONTEXT  (max 25 pts)
#    Increased from 10 pts because enrichment quality directly affects how
#    actionable an indicator is for detection and hunting.
#
#    Presence bonuses:
#      malware family:   +8 pts  — primary attribution label for rule generation
#      ATT&CK technique: +7 pts  — hunting and triage context
#      ASN resolved:     +5 pts  — infrastructure pivot
#      geolocation:      +3 pts  — campaign clustering signal
#    Total if fully enriched: 23 pts (leaving 2 pts headroom for rounding).
#
#    IOC-type enrichment expectation:
#      IP indicators can always be geolocated. If an IP has no location data
#      AND no ASN, it has not been enriched yet. A small "enrichment pending"
#      penalty is applied so high-volume, freshly-ingested IPs start with a
#      slightly lower score until the enrichment pass runs.
#      Penalty: -2 pts if ioc_type is IP and both ASN and geolocation are absent.
# ---------------------------------------------------------------------------

MAX_ACTIVITY_POINTS: float = 45.0
RECENCY_HALF_LIFE_DAYS: float = 30.0

MAX_CORROBORATION_POINTS: float = 20.0
MAX_CORROBORATION_FEEDS: int = 4  # treat ≥4 feeds as fully corroborated

MAX_HINT_POINTS: float = 10.0

MAX_CONTEXT_POINTS: float = 25.0
CONTEXT_MALWARE_FAMILY_POINTS: float = 8.0
CONTEXT_ATTACK_POINTS: float = 7.0
CONTEXT_ASN_POINTS: float = 5.0
CONTEXT_GEO_POINTS: float = 3.0
CONTEXT_IP_ENRICHMENT_PENDING_PENALTY: float = -2.0


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
    """Return the complete, reproducible confidence snapshot for one observation.

    The result is a deterministic analyst-prioritisation heuristic, not a
    probability.  Each stored snapshot includes the formula version and
    evaluation timestamp so later formula changes do not silently alter
    historical records.
    """
    current = now or datetime.now(UTC)
    current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)

    last_seen = ioc.last_seen
    last_seen = last_seen.replace(tzinfo=UTC) if last_seen.tzinfo is None else last_seen.astimezone(UTC)
    age_days = max(0.0, (current - last_seen).total_seconds() / 86_400)

    # ------------------------------------------------------------------
    # Component 1: Combined activity (reputation × recency)
    # ------------------------------------------------------------------
    reputation = SOURCE_REPUTATION.get(ioc.source_feed.lower(), _DEFAULT_REPUTATION)
    recency_factor = math.exp(-age_days / RECENCY_HALF_LIFE_DAYS)
    activity_score = round(MAX_ACTIVITY_POINTS * reputation * recency_factor, 1)
    activity_evidence = (
        f"{ioc.source_feed} reputation {reputation:.2f}, "
        f"recency factor {recency_factor:.3f} ({age_days:.1f} days old)"
    )

    # ------------------------------------------------------------------
    # Component 2: Independent corroboration (logarithmic)
    # ------------------------------------------------------------------
    feed_count = max(1, corroborating_feeds)
    if feed_count <= 1:
        corroboration_score = 0.0
        corroboration_evidence = "Single source — no independent corroboration"
    else:
        capped_count = min(feed_count, MAX_CORROBORATION_FEEDS)
        corroboration_score = round(
            MAX_CORROBORATION_POINTS
            * math.log(capped_count)
            / math.log(MAX_CORROBORATION_FEEDS),
            1,
        )
        corroboration_evidence = (
            f"{feed_count} provenance-isolated source feed{'s' if feed_count != 1 else ''}"
        )

    # ------------------------------------------------------------------
    # Component 3: Feed confidence hint
    # ------------------------------------------------------------------
    hint = ioc.source_confidence_hint
    if hint is not None and 0.0 <= hint <= 100.0:
        hint_score = round(MAX_HINT_POINTS * (hint / 100.0), 1)
        hint_evidence = f"Feed-provided confidence hint: {hint:.0f}/100"
    else:
        hint_score = 0.0
        hint_evidence = "No feed confidence hint available"

    # ------------------------------------------------------------------
    # Component 4: Analytic context
    # ------------------------------------------------------------------
    context_items: list[tuple[str, float, bool]] = [
        ("malware family", CONTEXT_MALWARE_FAMILY_POINTS, bool(ioc.malware_family)),
        ("ATT&CK technique", CONTEXT_ATTACK_POINTS, bool(ioc.attack_technique_ids)),
        ("ASN resolved", CONTEXT_ASN_POINTS, bool(ioc.asn)),
        ("geolocation", CONTEXT_GEO_POINTS, ioc.latitude is not None and ioc.longitude is not None),
    ]
    context_raw = sum(pts for _, pts, present in context_items if present)
    present_labels = [label for label, _, present in context_items if present]

    # Apply enrichment-pending penalty for un-enriched IP indicators
    is_ip = ioc.ioc_type.value == "ip"
    enrichment_pending = is_ip and not ioc.asn and ioc.latitude is None
    if enrichment_pending:
        context_raw += CONTEXT_IP_ENRICHMENT_PENDING_PENALTY
        present_labels.append("enrichment pending (IP not yet geolocated)")

    context_score = round(max(0.0, context_raw), 1)
    context_evidence = ", ".join(present_labels) if present_labels else "No enrichment context"

    # ------------------------------------------------------------------
    # Assemble components and total
    # ------------------------------------------------------------------
    components = (
        ConfidenceComponent(
            key="combined_activity",
            label="Source reputation × recency",
            score=activity_score,
            max_score=MAX_ACTIVITY_POINTS,
            evidence=activity_evidence,
        ),
        ConfidenceComponent(
            key="corroboration",
            label="Independent corroboration",
            score=corroboration_score,
            max_score=MAX_CORROBORATION_POINTS,
            evidence=corroboration_evidence,
        ),
        ConfidenceComponent(
            key="feed_hint",
            label="Feed confidence hint",
            score=hint_score,
            max_score=MAX_HINT_POINTS,
            evidence=hint_evidence,
        ),
        ConfidenceComponent(
            key="analytic_context",
            label="Analytic context",
            score=context_score,
            max_score=MAX_CONTEXT_POINTS,
            evidence=context_evidence,
        ),
    )

    total = round(min(100.0, max(0.0, sum(c.score for c in components))), 1)
    return ConfidenceBreakdown(
        total=total,
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
    """Score from combined activity, corroboration, feed hint, and analytic context."""
    return confidence_breakdown(ioc, corroborating_feeds=corroborating_feeds, now=now).total


class ConfidenceService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def recalculate(self) -> dict[str, int | float]:
        async with self.session_factory() as session:
            indicators = list((await session.scalars(select(IOC))).all())
            feed_counts: Counter[int] = Counter()
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
                ioc.confidence_components = [c.as_dict() for c in breakdown.components]
                total += ioc.confidence_score

            await session.commit()

        return {
            "updated": len(indicators),
            "average_score": round(total / len(indicators), 1) if indicators else 0.0,
            "corroborated": sum(count for feeds, count in feed_counts.items() if feeds > 1),
        }
