from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query
from sqlalchemy import case, func, select

from app.analysis_scope import resolve_analysis_scope, scope_from_counts
from app.api.dependencies import SessionDep, SettingsDep
from app.api.schemas import CountBucket, CountryBucket, SummaryStats, TechniqueTrend
from app.models import IOC, AttackTechnique, Campaign, FeedRun, FeedRunStatus

router = APIRouter(prefix="/stats", tags=["statistics"])


@router.get("/summary", response_model=SummaryStats)
async def summary(session: SessionDep, settings: SettingsDep) -> SummaryStats:
    now = datetime.now(UTC)
    total, demo_iocs, live_iocs = (
        await session.execute(
            select(
                func.count(IOC.id),
                func.coalesce(func.sum(case((IOC.is_demo.is_(True), 1), else_=0)), 0),
                func.coalesce(func.sum(case((IOC.is_demo.is_(False), 1), else_=0)), 0),
            )
        )
    ).one()
    total = int(total)
    demo_iocs = int(demo_iocs)
    live_iocs = int(live_iocs)
    scope = scope_from_counts(demo_iocs, live_iocs)
    ioc_scope = scope.ioc_condition()
    geolocated = (
        await session.scalar(
            select(func.count(IOC.id)).where(
                ioc_scope,
                IOC.latitude.is_not(None),
                IOC.longitude.is_not(None),
            )
        )
        or 0
    )
    high_confidence = (
        await session.scalar(
            select(func.count(IOC.id)).where(ioc_scope, IOC.confidence_score >= 70)
        )
        or 0
    )
    campaigns = (
        await session.scalar(
            select(func.count(Campaign.id)).where(
                Campaign.is_demo.is_(scope.included_is_demo)
                if scope.included_is_demo is not None
                else Campaign.id.is_(None)
            )
        )
        or 0
    )
    countries = (
        await session.scalar(
            select(func.count(func.distinct(IOC.country_code))).where(
                ioc_scope, IOC.country_code.is_not(None)
            )
        )
        or 0
    )
    ingestion_last_hour = (
        await session.scalar(
            select(func.count(IOC.id)).where(ioc_scope, IOC.created_at >= now - timedelta(hours=1))
        )
        or 0
    )
    has_operational_runs = bool(
        await session.scalar(
            select(func.count(FeedRun.id)).where(FeedRun.feed_name.not_like("demo-%"))
        )
    )
    feed_scope = (
        FeedRun.feed_name.like("demo-%")
        if scope.analysis_scope == "demo" and not has_operational_runs
        else FeedRun.feed_name.not_like("demo-%")
    )
    latest_runs = list(
        (
            await session.scalars(
                select(FeedRun).where(feed_scope).order_by(FeedRun.started_at.desc()).limit(25)
            )
        ).all()
    )
    latest_by_feed: dict[str, FeedRun] = {}
    for run in latest_runs:
        feed_key = run.feed_name.removeprefix("demo-")
        latest_by_feed.setdefault(feed_key, run)
    expected_feeds = ("urlhaus", "threatfox", "feodo")
    healthy = sum(
        latest_by_feed.get(feed) is not None
        and _feed_run_is_healthy(
            latest_by_feed[feed],
            now=now,
            freshness=timedelta(hours=settings.feed_sync_hours * 2),
        )
        for feed in expected_feeds
    )
    feed_health = round(healthy / len(expected_feeds) * 100, 1)
    recent = (
        await session.scalar(
            select(func.count(IOC.id)).where(ioc_scope, IOC.created_at >= now - timedelta(hours=24))
        )
        or 0
    )
    previous = (
        await session.scalar(
            select(func.count(IOC.id)).where(
                ioc_scope,
                IOC.created_at >= now - timedelta(hours=48),
                IOC.created_at < now - timedelta(hours=24),
            )
        )
        or 0
    )
    indicator_trend = round((recent - previous) / previous * 100, 1) if previous else 0.0
    return SummaryStats(
        total_iocs=total,
        demo_iocs=demo_iocs,
        live_iocs=live_iocs,
        corpus_mode=scope.corpus_mode,
        analysis_scope=scope.analysis_scope,
        geolocated_iocs=geolocated,
        high_confidence_iocs=high_confidence,
        active_campaigns=campaigns,
        affected_countries=countries,
        ingestion_last_hour=ingestion_last_hour,
        feed_health=feed_health,
        trend={
            "indicators": indicator_trend,
            "confidence": 0.0,
            "campaigns": 0.0,
            "countries": 0.0,
        },
        generated_at=now,
    )


def _feed_run_is_healthy(run: FeedRun, *, now: datetime, freshness: timedelta) -> bool:
    completed = run.completed_at or run.started_at
    if completed.tzinfo is None:
        completed = completed.replace(tzinfo=UTC)
    else:
        completed = completed.astimezone(UTC)
    return run.status is FeedRunStatus.SUCCEEDED and completed >= now - freshness


@router.get("/by-country", response_model=list[CountryBucket])
async def by_country(
    session: SessionDep, limit: int = Query(default=50, ge=1, le=250)
) -> list[CountryBucket]:
    scope = await resolve_analysis_scope(session)
    rows = (
        await session.execute(
            select(
                IOC.country,
                IOC.country_code,
                func.count(IOC.id),
                func.avg(IOC.confidence_score),
            )
            .where(scope.ioc_condition(), IOC.country.is_not(None))
            .group_by(IOC.country, IOC.country_code)
            .order_by(func.count(IOC.id).desc())
            .limit(limit)
        )
    ).all()
    return [
        CountryBucket(
            country=country,
            country_code=country_code,
            count=count,
            average_confidence=round(float(average or 0), 1),
        )
        for country, country_code, count, average in rows
    ]


@router.get("/by-malware-family", response_model=list[CountBucket])
async def by_malware_family(
    session: SessionDep, limit: int = Query(default=25, ge=1, le=250)
) -> list[CountBucket]:
    scope = await resolve_analysis_scope(session)
    rows = (
        await session.execute(
            select(IOC.malware_family, func.count(IOC.id))
            .where(scope.ioc_condition(), IOC.malware_family.is_not(None))
            .group_by(IOC.malware_family)
            .order_by(func.count(IOC.id).desc())
            .limit(limit)
        )
    ).all()
    return [CountBucket(key=family, count=count) for family, count in rows]


@router.get("/techniques/trending", response_model=list[TechniqueTrend])
async def trending_techniques(
    session: SessionDep,
    days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[TechniqueTrend]:
    since = datetime.now(UTC) - timedelta(days=days)
    scope = await resolve_analysis_scope(session)
    arrays = list(
        (
            await session.scalars(
                select(IOC.attack_technique_ids).where(
                    scope.ioc_condition(), IOC.last_seen >= since
                )
            )
        ).all()
    )
    counts = Counter(technique for values in arrays for technique in (values or []))
    top = counts.most_common(limit)
    catalog = {
        technique.technique_id: technique
        for technique in (
            await session.scalars(
                select(AttackTechnique).where(
                    AttackTechnique.technique_id.in_([item[0] for item in top])
                )
            )
        ).all()
    }
    return [
        TechniqueTrend(
            technique_id=technique_id,
            name=catalog.get(technique_id).name if technique_id in catalog else None,
            tactic=catalog.get(technique_id).tactic if technique_id in catalog else None,
            count=count,
        )
        for technique_id, count in top
    ]
