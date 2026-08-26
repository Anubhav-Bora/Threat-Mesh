from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.analysis_scope import resolve_analysis_scope
from app.detection_rules.generator import detection_key, generate_rule
from app.models import IOC, DetectionRule, RuleType


class DetectionRuleService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def generate(self, *, minimum_confidence: float, limit: int) -> dict[str, int | str]:
        async with self.session_factory() as session:
            scope = await resolve_analysis_scope(session)
            scope_is_demo = scope.included_is_demo
            if scope_is_demo is None:
                return {
                    "analysis_scope": "none",
                    "iocs_considered": 0,
                    "unique_detections": 0,
                    "created": 0,
                    "updated": 0,
                    "removed": 0,
                    "unsupported": 0,
                }

            # Detection identities are intentionally unique across the persisted
            # active corpus. Remove stale rules from the excluded provenance before
            # upserting the selected live-first scope.
            excluded = await session.execute(
                delete(DetectionRule).where(
                    DetectionRule.ioc_id.in_(
                        select(IOC.id).where(IOC.is_demo.is_(not scope_is_demo))
                    )
                )
            )
            await session.flush()
            excluded_removed = max(0, int(getattr(excluded, "rowcount", 0) or 0))
            selected_keys = (
                select(
                    IOC.ioc_type.label("ioc_type"),
                    IOC.indicator_key.label("indicator_key"),
                    func.max(IOC.confidence_score).label("maximum_confidence"),
                )
                .where(
                    IOC.confidence_score >= minimum_confidence,
                    IOC.is_demo.is_(scope_is_demo),
                )
                .group_by(IOC.ioc_type, IOC.indicator_key)
                .order_by(
                    func.max(IOC.confidence_score).desc(),
                    IOC.ioc_type,
                    IOC.indicator_key,
                )
                .limit(limit)
                .subquery()
            )
            indicators = list(
                (
                    await session.scalars(
                        select(IOC)
                        .join(
                            selected_keys,
                            and_(
                                IOC.ioc_type == selected_keys.c.ioc_type,
                                IOC.indicator_key == selected_keys.c.indicator_key,
                                IOC.is_demo.is_(scope_is_demo),
                            ),
                        )
                        .order_by(
                            selected_keys.c.maximum_confidence.desc(),
                            IOC.ioc_type,
                            IOC.indicator_key,
                            IOC.confidence_score.desc(),
                            IOC.source_feed,
                            IOC.id,
                        )
                    )
                ).all()
            )
            groups: dict[str, list[IOC]] = defaultdict(list)
            for ioc in indicators:
                groups[detection_key(ioc)].append(ioc)

            existing_rules = {
                (rule.detection_key, rule.rule_type): rule
                for rule in (
                    await session.scalars(
                        select(DetectionRule)
                        .join(IOC, DetectionRule.ioc_id == IOC.id)
                        .where(IOC.is_demo.is_(scope_is_demo))
                    )
                ).all()
            }
            created = updated = unsupported = 0
            desired_rules: set[tuple[str, RuleType]] = set()
            now = datetime.now(UTC)
            for identity, evidence in groups.items():
                ioc = evidence[0]
                sources = sorted({item.source_feed for item in evidence})
                techniques = sorted(
                    {technique for item in evidence for technique in item.attack_technique_ids}
                )
                for rule_type in RuleType:
                    text = generate_rule(
                        ioc,
                        rule_type,
                        corroborating_sources=sources,
                        technique_ids=techniques,
                    )
                    if text is None:
                        unsupported += 1
                        continue
                    desired_rules.add((identity, rule_type))
                    existing = existing_rules.get((identity, rule_type))
                    if existing:
                        existing.ioc_id = ioc.id
                        existing.rule_text = text
                        existing.corroborating_sources = sources
                        existing.generated_at = now
                        updated += 1
                    else:
                        session.add(
                            DetectionRule(
                                ioc_id=ioc.id,
                                detection_key=identity,
                                rule_type=rule_type,
                                rule_text=text,
                                corroborating_sources=sources,
                            )
                        )
                        created += 1
            removed = excluded_removed
            for identity, rule in existing_rules.items():
                if identity not in desired_rules:
                    await session.delete(rule)
                    removed += 1
            await session.commit()
        return {
            "analysis_scope": scope.analysis_scope,
            "iocs_considered": len(indicators),
            "unique_detections": len(groups),
            "created": created,
            "updated": updated,
            "removed": removed,
            "unsupported": unsupported,
        }
