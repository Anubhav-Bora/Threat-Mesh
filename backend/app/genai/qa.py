from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.analysis_scope import resolve_analysis_scope
from app.genai.prompts import QA_SYSTEM
from app.genai.providers import LLMProvider, LLMResponse
from app.genai.reports import top_counts, top_techniques
from app.models import IOC, Campaign, IOCType, Report


class RetrievalQAService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        provider: LLMProvider,
        *,
        max_rows: int = 100,
    ) -> None:
        self.session_factory = session_factory
        self.provider = provider
        self.max_rows = max_rows

    async def answer(
        self,
        question: str,
        *,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> tuple[LLMResponse, dict[str, object]]:
        facts = await self.retrieve(question, date_from=date_from, date_to=date_to)
        prompt = (
            f"User question:\n{question}\n\nRetrieved ThreatMesh facts (JSON):\n"
            f"```json\n{json.dumps(facts, indent=2, default=str)}\n```\n"
            "Answer using only these facts."
        )
        response = await self.provider.generate(prompt, system_instruction=QA_SYSTEM)
        return response, facts

    async def retrieve(
        self,
        question: str,
        *,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> dict[str, object]:
        start, end = _question_period(question, date_from=date_from, date_to=date_to)
        async with self.session_factory() as session:
            period_bounds = (IOC.last_seen >= start, IOC.last_seen < end)
            scope = await resolve_analysis_scope(session, *period_bounds)
            scoped_period = [*period_bounds, scope.ioc_condition()]
            filters = list(scoped_period)
            lower = question.lower()
            if re.search(r"\bip(s| addresses?)?\b", lower):
                filters.append(IOC.ioc_type == IOCType.IP)
            elif re.search(r"\bdomain(s)?\b", lower):
                filters.append(IOC.ioc_type == IOCType.DOMAIN)
            elif re.search(r"\burl(s)?\b", lower):
                filters.append(IOC.ioc_type == IOCType.URL)

            # Constrained retrieval: match only values already present in database dimensions.
            families = list(
                (
                    await session.scalars(
                        select(IOC.malware_family)
                        .where(*scoped_period, IOC.malware_family.is_not(None))
                        .distinct()
                        .limit(1000)
                    )
                ).all()
            )
            family_match = _match_family_dimension(question, families)
            if family_match:
                filters.append(IOC.malware_family == family_match)

            country_dimensions = list(
                (
                    await session.execute(
                        select(IOC.country, IOC.country_code)
                        .where(*scoped_period, IOC.country.is_not(None))
                        .distinct()
                        .limit(300)
                    )
                ).all()
            )
            country_match = _match_country_dimension(question, country_dimensions)
            if country_match:
                country, country_code = country_match
                filters.append(or_(IOC.country == country, IOC.country_code == country_code))
            matching_observation_count = int(
                await session.scalar(select(func.count(IOC.id)).where(*filters)) or 0
            )
            semantic_matches = (
                select(IOC.ioc_type, IOC.indicator_key).where(*filters).distinct().subquery()
            )
            matching_ioc_count = int(
                await session.scalar(select(func.count()).select_from(semantic_matches)) or 0
            )
            detail_limit = min(self.max_rows, 25)
            rows = list(
                (
                    await session.scalars(
                        select(IOC)
                        .where(*filters)
                        .order_by(IOC.confidence_score.desc(), IOC.last_seen.desc(), IOC.id.desc())
                        .limit(detail_limit)
                    )
                ).all()
            )
            matching_campaign_ids = (
                select(IOC.cluster_id).where(*filters, IOC.cluster_id.is_not(None)).distinct()
            )
            rank_campaigns_by_confidence = bool(
                re.search(r"\bcampaigns?\b", question, re.I)
                and re.search(r"\b(highest|average|confidence)\b", question, re.I)
            )
            average_confidence = Campaign.shared_attributes["observed_context"][
                "average_ioc_confidence"
            ].as_float()
            campaign_order = (
                (average_confidence.desc(), Campaign.ioc_count.desc(), Campaign.id)
                if rank_campaigns_by_confidence
                else (Campaign.ioc_count.desc(), Campaign.id)
            )
            campaigns = list(
                (
                    await session.scalars(
                        select(Campaign)
                        .where(
                            Campaign.id.in_(matching_campaign_ids),
                            Campaign.last_seen >= start,
                            Campaign.first_seen < end,
                            Campaign.is_demo.is_(scope.included_is_demo)
                            if scope.included_is_demo is not None
                            else Campaign.id.is_(None),
                        )
                        .order_by(*campaign_order)
                        .limit(10)
                    )
                ).all()
            )
            wants_reports = bool(
                re.search(
                    r"\breports?\b|\bweekly\s+(summary|briefing)\b",
                    question,
                    re.I,
                )
            )
            reports = (
                list(
                    (
                        await session.scalars(
                            select(Report)
                            .where(
                                Report.period_end > start,
                                Report.period_start < end,
                                Report.is_demo.is_(scope.included_is_demo)
                                if scope.included_is_demo is not None
                                else Report.id.is_(None),
                            )
                            .order_by(Report.created_at.desc(), Report.id.desc())
                            .limit(3)
                        )
                    ).all()
                )
                if wants_reports
                else []
            )
            filter_tuple = tuple(filters)
            families_count = await top_counts(
                session,
                IOC.malware_family,
                filter_tuple,
                limit=10,
                null_label="Unattributed",
            )
            countries = await top_counts(
                session, IOC.country, filter_tuple, limit=10, null_label="Unknown"
            )
            techniques = await top_techniques(session, filter_tuple, limit=15)
        return {
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "analysis_scope": scope.analysis_scope,
            "included_provenance": scope.analysis_scope,
            "period_corpus_mode": scope.corpus_mode,
            "filters": {
                "malware_family": family_match,
                "country": country_match[0] if country_match else None,
                "country_code": country_match[1] if country_match else None,
            },
            "matching_ioc_count": matching_ioc_count,
            "matching_observation_count": matching_observation_count,
            "retrieved_observation_count": len(rows),
            "top_malware_families": families_count,
            "observed_host_countries": countries,
            "attack_techniques": techniques,
            "indicators": [
                {
                    "id": ioc.id,
                    "record_id": f"ioc:{ioc.id}",
                    "value": ioc.ioc_value,
                    "type": ioc.ioc_type.value,
                    "port": ioc.port,
                    "family": ioc.malware_family,
                    "confidence": ioc.confidence_score,
                    "last_seen": ioc.last_seen.isoformat(),
                    "country": ioc.country,
                    "asn": ioc.asn,
                    "source": ioc.source_feed,
                    "is_demo": ioc.is_demo,
                    "campaign_id": ioc.cluster_id,
                    "technique_ids": list(ioc.attack_technique_ids or []),
                }
                for ioc in rows
            ],
            "campaigns": [_campaign_fact(campaign) for campaign in campaigns],
            "recent_reports": [
                {
                    "id": report.id,
                    "record_id": f"report:{report.id}",
                    "title": report.title,
                    "period_start": report.period_start.isoformat(),
                    "period_end": report.period_end.isoformat(),
                    "provider": report.provider,
                    "is_demo": report.is_demo,
                    "excerpt": report.report_text[:1500],
                }
                for report in reports
            ],
            "truncated": matching_observation_count > len(rows),
        }


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _question_period(
    question: str,
    *,
    date_from: datetime | None,
    date_to: datetime | None,
) -> tuple[datetime, datetime]:
    end = _utc(date_to or datetime.now(UTC))
    if date_from is not None:
        return _utc(date_from), end
    if re.search(r"\btoday\b", question, re.I):
        return end.replace(hour=0, minute=0, second=0, microsecond=0), end
    if re.search(r"\bthis\s+month\b", question, re.I):
        return end.replace(day=1, hour=0, minute=0, second=0, microsecond=0), end
    explicit_days = re.search(r"\b(?:last|past)\s+(\d{1,4})\s+days?\b", question, re.I)
    if explicit_days:
        days = min(365, max(1, int(explicit_days.group(1))))
        return end - timedelta(days=days), end
    if re.search(r"\b(?:this|past|last)\s+week\b", question, re.I):
        return end - timedelta(days=7), end
    return end - timedelta(days=30), end


def _match_country_dimension(
    question: str, dimensions: list[tuple[str | None, str | None]]
) -> tuple[str, str | None] | None:
    explicit_codes = set(re.findall(r"\b[A-Z]{2}\b", question))
    explicit_codes.update(
        code.upper() for code in re.findall(r"\bcountry\s*:\s*([A-Za-z]{2})\b", question, re.I)
    )
    for country, code in sorted(dimensions, key=lambda item: len(item[0] or ""), reverse=True):
        if not country:
            continue
        full_name = re.search(rf"(?<!\w){re.escape(country)}(?!\w)", question, re.I)
        if full_name or (code and code.upper() in explicit_codes):
            return country, code
    return None


def _match_family_dimension(question: str, families: list[str | None]) -> str | None:
    for family in sorted((value for value in families if value), key=len, reverse=True):
        explicit = re.search(rf"\bfamily\s*:\s*{re.escape(family)}(?!\w)", question, re.I)
        if explicit:
            return family
        if len(family) > 3 and re.search(rf"(?<!\w){re.escape(family)}(?!\w)", question, re.I):
            return family
    return None


def _campaign_fact(campaign: Campaign) -> dict[str, object]:
    shared = campaign.shared_attributes or {}
    evidence = shared.get("relationship_evidence") or {}
    context = shared.get("observed_context") or {}
    return {
        "id": campaign.id,
        "record_id": f"campaign:{campaign.id}",
        "is_demo": campaign.is_demo,
        "label": campaign.label,
        "observation_count": context.get("observation_count", campaign.ioc_count),
        "unique_indicator_count": context.get("unique_indicator_count", 0),
        "average_ioc_confidence": context.get("average_ioc_confidence", 0),
        "relationship_evidence": evidence,
        "observed_context": context,
        "first_seen": campaign.first_seen.isoformat(),
        "last_seen": campaign.last_seen.isoformat(),
    }
