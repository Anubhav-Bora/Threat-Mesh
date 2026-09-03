from __future__ import annotations

import math
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Query
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.selectable import Subquery

from app.api.dependencies import SessionDep
from app.api.schemas import (
    GeoJSONFeatureCollection,
    GeoJSONPoint,
    IOCDetail,
    IOCFeature,
    IOCLineageResponse,
    IOCProperties,
)
from app.errors import AppError
from app.evidence import build_ioc_lineage
from app.models import IOC, IOCType
from app.models.entities import GeographyPoint

router = APIRouter(prefix="/iocs", tags=["indicators"])


@router.get("", response_model=GeoJSONFeatureCollection)
async def list_iocs(
    session: SessionDep,
    country: str | None = Query(default=None, max_length=128),
    malware_family: str | None = Query(default=None, max_length=255),
    ioc_type: IOCType | None = None,
    cluster_id: int | None = Query(default=None, ge=1),
    provenance: Literal["all", "live", "demo"] = "all",
    confidence_min: float = Query(default=0, ge=0, le=100),
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    near_lat: float | None = Query(default=None, ge=-90, le=90),
    near_lon: float | None = Query(default=None, ge=-180, le=180),
    radius_km: float | None = Query(default=None, gt=0, le=5000),
    search: str | None = Query(default=None, min_length=2, max_length=200),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
) -> GeoJSONFeatureCollection:
    date_from = _utc(date_from) if date_from else None
    date_to = _utc(date_to) if date_to else None
    if date_from and date_to and date_from >= date_to:
        raise AppError(422, "invalid_date_range", "date_from must be earlier than date_to")
    spatial_values = (near_lat, near_lon, radius_km)
    if any(value is not None for value in spatial_values) and not all(
        value is not None for value in spatial_values
    ):
        raise AppError(
            422,
            "incomplete_spatial_filter",
            "near_lat, near_lon, and radius_km must be provided together",
        )
    filters = [IOC.confidence_score >= confidence_min]
    if provenance == "live":
        filters.append(IOC.is_demo.is_(False))
    elif provenance == "demo":
        filters.append(IOC.is_demo.is_(True))
    if country:
        filters.append(or_(IOC.country == country, IOC.country_code == country.upper()))
    if malware_family:
        filters.append(IOC.malware_family.ilike(f"%{malware_family}%"))
    if ioc_type:
        filters.append(IOC.ioc_type == ioc_type)
    if cluster_id:
        filters.append(IOC.cluster_id == cluster_id)
    if date_from:
        filters.append(IOC.last_seen >= date_from)
    if date_to:
        filters.append(IOC.first_seen < date_to)
    if near_lat is not None and near_lon is not None and radius_km is not None:
        filters.append(IOC.location.is_not(None))
        if session.bind and session.bind.dialect.name == "postgresql":
            center = func.ST_SetSRID(func.ST_MakePoint(near_lon, near_lat), 4326).cast(
                GeographyPoint()
            )
            filters.append(func.ST_DWithin(IOC.location, center, radius_km * 1000))
        else:
            # SQLite demo fallback: a conservative coordinate bounding box.
            latitude_delta = radius_km / 111.0
            longitude_scale = max(0.01, abs(math.cos(math.radians(near_lat))))
            longitude_delta = radius_km / (111.0 * longitude_scale)
            filters.extend(
                [
                    IOC.latitude.between(near_lat - latitude_delta, near_lat + latitude_delta),
                    IOC.longitude.between(near_lon - longitude_delta, near_lon + longitude_delta),
                ]
            )
    if search:
        escaped = search.replace("%", "\\%").replace("_", "\\_")
        filters.append(
            or_(
                IOC.ioc_value.ilike(f"%{escaped}%", escape="\\"),
                IOC.malware_family.ilike(f"%{escaped}%", escape="\\"),
                IOC.asn_org.ilike(f"%{escaped}%", escape="\\"),
            )
        )
    total = await session.scalar(select(func.count(IOC.id)).where(*filters)) or 0
    page_ids = (
        select(IOC.id)
        .where(*filters)
        .order_by(IOC.last_seen.desc(), IOC.id.desc())
        .offset(offset)
        .limit(limit)
        .subquery()
    )
    rows = list(
        (
            await session.scalars(
                select(IOC)
                .join(page_ids, page_ids.c.id == IOC.id)
                .order_by(IOC.last_seen.desc(), IOC.id.desc())
            )
        ).all()
    )
    provenance = await _page_provenance(session, page_ids)
    return GeoJSONFeatureCollection(
        features=[_feature(ioc, provenance) for ioc in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{ioc_id}", response_model=IOCDetail)
async def get_ioc(ioc_id: int, session: SessionDep) -> IOCDetail:
    ioc = await session.get(IOC, ioc_id)
    if ioc is None:
        raise AppError(404, "ioc_not_found", f"IOC {ioc_id} was not found")
    sources = list(
        (
            await session.scalars(
                select(IOC.source_feed)
                .where(
                    IOC.ioc_type == ioc.ioc_type,
                    IOC.indicator_key == ioc.indicator_key,
                    IOC.is_demo.is_(ioc.is_demo),
                )
                .distinct()
                .order_by(IOC.source_feed)
            )
        ).all()
    )
    return IOCDetail.model_validate(ioc).model_copy(
        update={
            "corroborating_feeds": len(sources),
            "corroborating_sources": sources,
        }
    )


@router.get("/{ioc_id}/lineage", response_model=IOCLineageResponse)
async def get_ioc_lineage(ioc_id: int, session: SessionDep) -> IOCLineageResponse:
    ioc = await session.get(IOC, ioc_id)
    if ioc is None:
        raise AppError(404, "ioc_not_found", f"IOC {ioc_id} was not found")
    return IOCLineageResponse.model_validate(await build_ioc_lineage(session, ioc))


async def _page_provenance(
    session: AsyncSession, page_ids: Subquery
) -> dict[tuple[bool, IOCType, str], list[str]]:
    selected_keys = (
        select(
            IOC.ioc_type.label("ioc_type"),
            IOC.indicator_key.label("indicator_key"),
            IOC.is_demo.label("is_demo"),
        )
        .join(page_ids, page_ids.c.id == IOC.id)
        .distinct()
        .subquery()
    )
    rows = (
        await session.execute(
            select(IOC.is_demo, IOC.ioc_type, IOC.indicator_key, IOC.source_feed)
            .join(
                selected_keys,
                and_(
                    IOC.is_demo == selected_keys.c.is_demo,
                    IOC.ioc_type == selected_keys.c.ioc_type,
                    IOC.indicator_key == selected_keys.c.indicator_key,
                ),
            )
            .distinct()
            .order_by(IOC.is_demo, IOC.ioc_type, IOC.indicator_key, IOC.source_feed)
        )
    ).all()
    result: dict[tuple[bool, IOCType, str], list[str]] = {}
    for is_demo, ioc_type, indicator_key, source in rows:
        result.setdefault((is_demo, ioc_type, indicator_key), []).append(source)
    return result


def _feature(ioc: IOC, provenance: dict[tuple[bool, IOCType, str], list[str]]) -> IOCFeature:
    geometry = None
    if ioc.latitude is not None and ioc.longitude is not None:
        geometry = GeoJSONPoint(coordinates=(ioc.longitude, ioc.latitude))
    sources = provenance.get((ioc.is_demo, ioc.ioc_type, ioc.indicator_key), [ioc.source_feed])
    return IOCFeature(
        id=ioc.id,
        geometry=geometry,
        properties=IOCProperties.model_validate(ioc).model_copy(
            update={
                "corroborating_feeds": len(sources),
                "corroborating_sources": sources,
            }
        ),
    )


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
