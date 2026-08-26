from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.api.dependencies import SessionDep
from app.api.schemas import CampaignDetail, CampaignSummary, IOCDetail
from app.errors import AppError
from app.models import Campaign

router = APIRouter(prefix="/campaigns", tags=["campaigns"])


@router.get("", response_model=list[CampaignSummary])
async def list_campaigns(
    session: SessionDep,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[CampaignSummary]:
    campaigns = list(
        (
            await session.scalars(
                select(Campaign).order_by(Campaign.last_seen.desc()).offset(offset).limit(limit)
            )
        ).all()
    )
    return [_summary(campaign) for campaign in campaigns]


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign(campaign_id: int, session: SessionDep) -> CampaignDetail:
    campaign = await session.scalar(
        select(Campaign).options(selectinload(Campaign.iocs)).where(Campaign.id == campaign_id)
    )
    if campaign is None:
        raise AppError(404, "campaign_not_found", f"Campaign {campaign_id} was not found")
    return CampaignDetail(
        **_summary(campaign).model_dump(),
        iocs=[IOCDetail.model_validate(ioc) for ioc in campaign.iocs],
    )


def _summary(campaign: Campaign) -> CampaignSummary:
    shared = campaign.shared_attributes or {}
    evidence = shared.get("relationship_evidence") or {}
    context = shared.get("observed_context") or {}
    return CampaignSummary(
        id=campaign.id,
        label=campaign.label,
        first_seen=campaign.first_seen,
        last_seen=campaign.last_seen,
        is_demo=campaign.is_demo,
        observation_count=int(context.get("observation_count") or campaign.ioc_count),
        unique_indicator_count=int(context.get("unique_indicator_count") or 0),
        summary_text=campaign.summary_text,
        average_ioc_confidence=float(context.get("average_ioc_confidence") or 0),
        relationship_evidence=evidence,
        observed_context=context,
        created_at=campaign.created_at,
        updated_at=campaign.updated_at,
    )
