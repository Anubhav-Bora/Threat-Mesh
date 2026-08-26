from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.enrichment import EnrichmentService, GeoResult
from app.models import IOC, GeoCache, IOCType
from tests.factories import make_ioc


class FakeGeoProvider:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def lookup(self, ip_address: str) -> GeoResult:
        self.calls.append(ip_address)
        return GeoResult(
            ip_address=ip_address,
            successful=True,
            country="United States",
            country_code="US",
            city="Mountain View",
            asn="AS15169",
            asn_org="Google LLC",
            latitude=37.4056,
            longitude=-122.0775,
        )


class SelectiveGeoProvider(FakeGeoProvider):
    async def lookup(self, ip_address: str) -> GeoResult:
        self.calls.append(ip_address)
        if ip_address == "8.8.4.4":
            return GeoResult(
                ip_address=ip_address,
                successful=False,
                failure_reason="temporary provider failure",
            )
        return GeoResult(
            ip_address=ip_address,
            successful=True,
            country="United States",
            latitude=37.4056,
            longitude=-122.0775,
        )


@pytest.mark.asyncio
async def test_enrichment_only_queries_literal_ip_rows(app, settings) -> None:
    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="8.8.8.8"))
        session.add(
            make_ioc(
                value="malicious.example.test",
                ioc_type=IOCType.DOMAIN,
                port=None,
                source="urlhaus",
            )
        )
        await session.commit()
    provider = FakeGeoProvider()
    service = EnrichmentService(app.state.database.session_factory, settings, provider=provider)
    result = await service.enrich_pending()
    assert result["processed"] == 1
    assert result["enriched"] == 1
    assert provider.calls == ["8.8.8.8"]
    async with app.state.database.session_factory() as session:
        ip_ioc = await session.scalar(select(IOC).where(IOC.ioc_type == IOCType.IP))
        domain = await session.scalar(select(IOC).where(IOC.ioc_type == IOCType.DOMAIN))
        assert ip_ioc.location == "SRID=4326;POINT(-122.0775 37.4056)"
        assert domain.latitude is None


@pytest.mark.asyncio
async def test_enrichment_negative_cache_prevents_starvation_and_expires(app, settings) -> None:
    settings.enrichment_batch_size = 2
    async with app.state.database.session_factory() as session:
        session.add(make_ioc(value="10.0.0.1", hours_old=1, source="feodo"))
        session.add(make_ioc(value="8.8.4.4", hours_old=2, source="threatfox"))
        session.add(make_ioc(value="8.8.8.8", hours_old=10, source="urlhaus"))
        await session.commit()

    provider = SelectiveGeoProvider()
    service = EnrichmentService(app.state.database.session_factory, settings, provider=provider)
    first = await service.enrich_pending()
    second = await service.enrich_pending()

    assert first == {
        "processed": 2,
        "enriched": 0,
        "cached": 0,
        "skipped": 1,
        "failed": 1,
    }
    assert second["processed"] == 1
    assert second["enriched"] == 1
    assert provider.calls == ["8.8.4.4", "8.8.8.8"]

    async with app.state.database.session_factory() as session:
        failures = list(
            (await session.scalars(select(GeoCache).where(GeoCache.successful.is_(False)))).all()
        )
        assert {entry.ip_address for entry in failures} == {"10.0.0.1", "8.8.4.4"}
        stale = datetime.now(UTC) - timedelta(days=settings.geolocation_cache_days + 1)
        for entry in failures:
            entry.fetched_at = stale
        await session.commit()

    retry = await service.enrich_pending(limit=2)
    assert retry["processed"] == 2
    assert retry["skipped"] == 1
    assert retry["failed"] == 1
    assert provider.calls.count("8.8.4.4") == 2
