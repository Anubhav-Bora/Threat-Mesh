from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.attack_mapping import AttackMappingService
from app.clustering import ClusteringService
from app.config import Settings
from app.detection_rules import DetectionRuleService
from app.enrichment import EnrichmentService
from app.ingestion import IngestionService
from app.scoring import ConfidenceService


class PipelineService:
    """One orchestration boundary shared by interactive, embedded, and cloud jobs."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings

    async def run_analysis(self) -> dict[str, Any]:
        mapping = await AttackMappingService(self.session_factory).map_indicators()
        scoring = await ConfidenceService(self.session_factory).recalculate()
        clustering = await ClusteringService(self.session_factory, self.settings).rebuild()
        rules = await DetectionRuleService(self.session_factory).generate(
            minimum_confidence=self.settings.minimum_rule_confidence,
            limit=1000,
        )
        return {
            "attack_mapping": mapping,
            "confidence": scoring,
            "clustering": clustering,
            "rules": rules,
        }

    async def run_full(self) -> dict[str, Any]:
        feeds = await IngestionService(self.session_factory, self.settings).sync_all()
        enrichment = await EnrichmentService(self.session_factory, self.settings).enrich_pending()
        analysis = await self.run_analysis()
        return {"feeds": feeds, "enrichment": enrichment, "analysis": analysis}
