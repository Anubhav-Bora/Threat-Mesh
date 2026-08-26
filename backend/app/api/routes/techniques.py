from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from app.api.dependencies import SessionDep
from app.models import AttackTechnique

router = APIRouter(prefix="/techniques", tags=["MITRE ATT&CK"])


@router.get("")
async def list_techniques(
    session: SessionDep, limit: int = Query(default=500, ge=1, le=1000)
) -> list[dict[str, object]]:
    techniques = list(
        (
            await session.scalars(
                select(AttackTechnique).order_by(AttackTechnique.technique_id).limit(limit)
            )
        ).all()
    )
    return [
        {
            "technique_id": item.technique_id,
            "tactic": item.tactic,
            "name": item.name,
            "description": item.description,
        }
        for item in techniques
    ]
