from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.attack_mapping.catalog import CURATED_TECHNIQUES, techniques_for_family
from app.models import IOC, AttackTechnique


class AttackMappingService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    async def seed_curated_techniques(self) -> int:
        async with self.session_factory() as session:
            count = await self._upsert_curated(session)
            await session.commit()
            return count

    async def map_indicators(self) -> dict[str, int]:
        async with self.session_factory() as session:
            await self._upsert_curated(session)
            indicators = list((await session.scalars(select(IOC))).all())
            mapped = 0
            for ioc in indicators:
                technique_ids = techniques_for_family(ioc.malware_family)
                if technique_ids != (ioc.attack_technique_ids or []):
                    ioc.attack_technique_ids = technique_ids
                    mapped += 1
            await session.commit()
        return {"processed": len(indicators), "mapped": mapped}

    async def load_stix_file(self, path: Path) -> dict[str, int]:
        raw = await asyncio.to_thread(path.read_text, encoding="utf-8")
        payload = json.loads(raw)
        return await self.load_stix_payload(payload)

    async def load_stix_payload(self, payload: dict[str, Any]) -> dict[str, int]:
        techniques = self.parse_stix(payload)
        async with self.session_factory() as session:
            updated = 0
            for data in techniques:
                existing = await session.get(AttackTechnique, data["technique_id"])
                if existing is None:
                    session.add(AttackTechnique(**data))
                else:
                    for key, value in data.items():
                        setattr(existing, key, value)
                updated += 1
            await session.commit()
        return {"loaded": updated}

    @staticmethod
    def parse_stix(payload: dict[str, Any]) -> list[dict[str, Any]]:
        parsed: list[dict[str, Any]] = []
        for item in payload.get("objects", []):
            if (
                item.get("type") != "attack-pattern"
                or item.get("revoked")
                or item.get("x_mitre_deprecated")
            ):
                continue
            reference = next(
                (
                    ref
                    for ref in item.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
                ),
                None,
            )
            if not reference:
                continue
            tactics = [phase.get("phase_name") for phase in item.get("kill_chain_phases", [])]
            modified = item.get("modified")
            parsed.append(
                {
                    "technique_id": reference["external_id"],
                    "tactic": ",".join(filter(None, tactics)) or "unknown",
                    "name": item.get("name", reference["external_id"]),
                    "description": item.get("description", ""),
                    "stix_id": item.get("id"),
                    "modified_at": datetime.fromisoformat(modified.replace("Z", "+00:00"))
                    if modified
                    else None,
                }
            )
        return parsed

    @staticmethod
    async def _upsert_curated(session: AsyncSession) -> int:
        count = 0
        for definition in CURATED_TECHNIQUES.values():
            existing = await session.get(AttackTechnique, definition.technique_id)
            if existing is None:
                session.add(
                    AttackTechnique(
                        technique_id=definition.technique_id,
                        tactic=definition.tactic,
                        name=definition.name,
                        description=definition.description,
                    )
                )
            count += 1
        return count
