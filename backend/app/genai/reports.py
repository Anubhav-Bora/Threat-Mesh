from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, cast, func, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from app.analysis_scope import resolve_analysis_scope
from app.errors import AppError
from app.genai.prompts import REPORT_SYSTEM
from app.genai.providers import LLMProvider
from app.models import IOC, Campaign, Report


class ReportService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        provider: LLMProvider,
    ) -> None:
        self.session_factory = session_factory
        self.provider = provider

    async def generate(
        self,
        *,
        period_start: datetime | None = None,
        period_end: datetime | None = None,
    ) -> Report:
        end = _utc(period_end or datetime.now(UTC))
        start = _utc(period_start or (end - timedelta(days=7)))
        async with self.session_factory() as session:
            facts = await self.collect_facts(session, start, end)
            if facts["analysis_scope"] == "none":
                raise AppError(
                    409,
                    "report_no_evidence",
                    "No IOC observations exist in the requested period; "
                    "report generation was not started.",
                    details={
                        "period_start": start.isoformat(),
                        "period_end": end.isoformat(),
                    },
                )
            prompt = (
                "Reporting period (UTC): "
                f"{start.isoformat()} through {end.isoformat()}\n\n"
                "Deterministically computed facts (JSON):\n"
                f"```json\n{json.dumps(facts, indent=2, default=str)}\n```\n"
                "Write the report. Do not add facts absent from this JSON."
            )
            response = await self.provider.generate(prompt, system_instruction=REPORT_SYSTEM)
            report = Report(
                period_start=start,
                period_end=end,
                title=f"ThreatMesh Weekly CTI Report — {end.date().isoformat()}",
                report_text=response.text,
                provider=response.provider,
                model=response.model,
                facts_json=facts,
                is_demo=facts["analysis_scope"] == "demo",
            )
            session.add(report)
            await session.commit()
            await session.refresh(report)
            return report

    @staticmethod
    async def collect_facts(
        session: AsyncSession, start: datetime, end: datetime
    ) -> dict[str, object]:
        start = _utc(start)
        end = _utc(end)
        period_bounds = (IOC.last_seen >= start, IOC.last_seen < end)
        scope = await resolve_analysis_scope(session, *period_bounds)
        period = (*period_bounds, scope.ioc_condition())
        total_observations, geolocated_observations, high_confidence_observations = (
            await session.execute(
                select(
                    func.count(IOC.id),
                    func.count(IOC.latitude),
                    func.coalesce(func.sum(case((IOC.confidence_score >= 70, 1), else_=0)), 0),
                ).where(*period)
            )
        ).one()
        semantic_indicators = (
            select(IOC.ioc_type, IOC.indicator_key).where(*period).distinct().subquery()
        )
        unique_indicator_count = int(
            await session.scalar(select(func.count()).select_from(semantic_indicators)) or 0
        )
        indicators = list(
            (
                await session.scalars(
                    select(IOC)
                    .where(*period)
                    .order_by(IOC.confidence_score.desc(), IOC.last_seen.desc(), IOC.id.desc())
                    .limit(25)
                )
            ).all()
        )
        campaigns = list(
            (
                await session.scalars(
                    select(Campaign)
                    .where(
                        Campaign.last_seen >= start,
                        Campaign.first_seen < end,
                        Campaign.is_demo.is_(scope.included_is_demo)
                        if scope.included_is_demo is not None
                        else Campaign.id.is_(None),
                    )
                    .order_by(Campaign.ioc_count.desc())
                    .limit(10)
                )
            ).all()
        )
        families = await top_counts(
            session, IOC.malware_family, period, limit=10, null_label="Unattributed"
        )
        countries = await top_counts(session, IOC.country, period, limit=10, null_label="Unknown")
        asns = await top_counts(session, IOC.asn, period, limit=10, null_label="Unknown")
        sources = await top_counts(session, IOC.source_feed, period, limit=20)
        ioc_types = await top_counts(session, IOC.ioc_type, period, limit=10)
        techniques = await top_techniques(session, period, limit=15)
        return {
            "analysis_scope": scope.analysis_scope,
            "included_provenance": scope.analysis_scope,
            "period_corpus_mode": scope.corpus_mode,
            "total_observations": int(total_observations),
            "unique_indicator_count": unique_indicator_count,
            "geolocated_observations": int(geolocated_observations),
            "high_confidence_observations": int(high_confidence_observations),
            "top_malware_families_by_observation": families,
            "top_observed_host_countries_by_observation": countries,
            "top_asns_by_observation": asns,
            "source_observation_distribution": sources,
            "ioc_type_observation_distribution": ioc_types,
            "attack_technique_observation_counts": techniques,
            "notable_campaigns": [
                {
                    "id": campaign.id,
                    "is_demo": campaign.is_demo,
                    "label": campaign.label,
                    "unique_indicator_count": campaign.ioc_count,
                    "observation_count": (campaign.shared_attributes or {})
                    .get("observed_context", {})
                    .get("observation_count", campaign.ioc_count),
                    "first_seen": campaign.first_seen.isoformat(),
                    "last_seen": campaign.last_seen.isoformat(),
                    "relationship_evidence": (campaign.shared_attributes or {}).get(
                        "relationship_evidence", {}
                    ),
                    "observed_context": (campaign.shared_attributes or {}).get(
                        "observed_context", {}
                    ),
                }
                for campaign in campaigns
            ],
            "sample_high_confidence_observations": [
                {
                    "value": ioc.ioc_value,
                    "type": ioc.ioc_type.value,
                    "port": ioc.port,
                    "family": ioc.malware_family,
                    "confidence": ioc.confidence_score,
                    "source_feed": ioc.source_feed,
                    "is_demo": ioc.is_demo,
                }
                for ioc in indicators
            ],
            "limitations": [
                "IP geolocation describes observed infrastructure and is approximate.",
                "Feed coverage is incomplete and indicators can become stale or be reused.",
                "Campaign clusters are analytic leads, not confirmed attribution.",
            ],
        }


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def top_counts(
    session: AsyncSession,
    column: ColumnElement[Any],
    period: tuple[ColumnElement[bool], ...],
    *,
    limit: int,
    null_label: str | None = None,
) -> list[list[object]]:
    dimension = func.coalesce(column, null_label) if null_label is not None else column
    count = func.count(IOC.id).label("ioc_count")
    rows = (
        await session.execute(
            select(dimension.label("dimension"), count)
            .where(*period)
            .group_by(dimension)
            .order_by(count.desc(), dimension)
            .limit(limit)
        )
    ).all()
    return [[_dimension_value(value), int(item_count)] for value, item_count in rows]


async def top_techniques(
    session: AsyncSession,
    period: tuple[ColumnElement[bool], ...],
    *,
    limit: int,
) -> list[list[object]]:
    dialect = session.bind.dialect.name if session.bind else "sqlite"
    if dialect == "postgresql":
        expanded = (
            func.jsonb_array_elements_text(cast(IOC.attack_technique_ids, JSONB))
            .table_valued("value")
            .lateral()
        )
    else:
        expanded = func.json_each(IOC.attack_technique_ids).table_valued("value")
    count = func.count().label("ioc_count")
    rows = (
        await session.execute(
            select(expanded.c.value, count)
            .select_from(IOC)
            .join(expanded, true())
            .where(*period)
            .group_by(expanded.c.value)
            .order_by(count.desc(), expanded.c.value)
            .limit(limit)
        )
    ).all()
    return [[str(value), int(item_count)] for value, item_count in rows]


def _dimension_value(value: object) -> object:
    return value.value if hasattr(value, "value") else value
