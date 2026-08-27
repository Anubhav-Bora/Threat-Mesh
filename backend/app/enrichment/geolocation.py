from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings
from app.models import IOC, GeoCache, IOCType


@dataclass(frozen=True)
class GeoResult:
    ip_address: str
    successful: bool
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    failure_reason: str | None = None


class RequestPacer:
    def __init__(self, requests_per_minute: int) -> None:
        self.interval = 60.0 / max(1, requests_per_minute)
        self.next_allowed = 0.0
        self.lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self.lock:
            now = time.monotonic()
            delay = self.next_allowed - now
            if delay > 0:
                await asyncio.sleep(delay)
            self.next_allowed = max(now, self.next_allowed) + self.interval


class IPAPIClient:
    def __init__(self, client: httpx.AsyncClient, settings: Settings) -> None:
        self.client = client
        self.settings = settings
        self.pacer = RequestPacer(settings.geolocation_requests_per_minute)

    async def lookup(self, ip_address: str) -> GeoResult:
        await self.pacer.wait()
        fields = "status,message,country,countryCode,city,lat,lon,as,asname,query"
        response = await self.client.get(
            f"{self.settings.geolocation_base_url.rstrip('/')}/{ip_address}",
            params={"fields": fields},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "success":
            return GeoResult(
                ip_address=ip_address,
                successful=False,
                failure_reason=str(payload.get("message") or "lookup failed")[:255],
            )
        as_field = str(payload.get("as") or "").strip()
        asn = as_field.split(" ", 1)[0] or None
        asn_org = payload.get("asname") or (as_field.split(" ", 1)[1] if " " in as_field else None)
        return GeoResult(
            ip_address=ip_address,
            successful=True,
            country=payload.get("country"),
            country_code=(payload.get("countryCode") or None),
            city=payload.get("city"),
            asn=asn,
            asn_org=asn_org,
            latitude=float(payload["lat"]) if payload.get("lat") is not None else None,
            longitude=float(payload["lon"]) if payload.get("lon") is not None else None,
        )


async def indicator_ip(ioc: IOC) -> str | None:
    candidate: str | None = None
    if ioc.ioc_type is IOCType.IP:
        candidate = ioc.ioc_value
    elif ioc.ioc_type is IOCType.URL:
        candidate = urlsplit(ioc.ioc_value).hostname
    if not candidate:
        return None
    try:
        address = ipaddress.ip_address(candidate)
        return str(address) if address.is_global else None
    except ValueError:
        # Never resolve known-malicious hostnames from the ingestion environment.
        return None


class EnrichmentService:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        settings: Settings,
        *,
        client: httpx.AsyncClient | None = None,
        provider: IPAPIClient | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.settings = settings
        self._client = client
        self._provider = provider

    async def enrich_pending(self, *, limit: int | None = None) -> dict[str, int]:
        if not self.settings.geolocation_enabled:
            return {"processed": 0, "enriched": 0, "cached": 0, "skipped": 0, "failed": 0}
        owns_client = self._client is None and self._provider is None
        client = self._client or httpx.AsyncClient(
            timeout=self.settings.http_timeout_seconds,
            headers={"User-Agent": self.settings.http_user_agent},
        )
        provider = self._provider or IPAPIClient(client, self.settings)
        stats = {"processed": 0, "enriched": 0, "cached": 0, "skipped": 0, "failed": 0}
        try:
            async with self.session_factory() as session:
                now = datetime.now(UTC)
                cache_age = timedelta(days=self.settings.geolocation_cache_days)
                stale_before = now - cache_age
                query = (
                    select(IOC)
                    .outerjoin(GeoCache, GeoCache.ip_address == IOC.ioc_value)
                    .where(
                        IOC.latitude.is_(None),
                        IOC.ioc_type == IOCType.IP,
                        or_(
                            GeoCache.ip_address.is_(None),
                            GeoCache.fetched_at < stale_before,
                            GeoCache.successful.is_(True),
                        ),
                    )
                    .order_by(IOC.last_seen.desc())
                    .limit(limit or self.settings.enrichment_batch_size)
                )
                indicators = list((await session.scalars(query)).all())
                batch_results: dict[str, GeoResult] = {}
                for ioc in indicators:
                    stats["processed"] += 1
                    ip_address = await indicator_ip(ioc)
                    if not ip_address:
                        # Persist policy skips as negative cache entries. Otherwise a recent
                        # private/reserved address would occupy every subsequent batch.
                        try:
                            literal_address = str(ipaddress.ip_address(ioc.ioc_value))
                        except ValueError:
                            literal_address = ioc.ioc_value
                        if literal_address not in batch_results:
                            cached = await session.get(GeoCache, literal_address)
                            result = GeoResult(
                                ip_address=literal_address,
                                successful=False,
                                failure_reason="non-public or invalid literal IP address",
                            )
                            await self._store_cache(session, result, cached, fetched_at=now)
                            batch_results[literal_address] = result
                        else:
                            stats["cached"] += 1
                        stats["skipped"] += 1
                        continue
                    if ip_address in batch_results:
                        result = batch_results[ip_address]
                        stats["cached"] += 1
                    else:
                        cached = await session.get(GeoCache, ip_address)
                        store_result = False
                        if cached and _as_utc(cached.fetched_at) >= stale_before:
                            result = _result_from_cache(cached)
                            stats["cached"] += 1
                        else:
                            try:
                                result = await provider.lookup(ip_address)
                            except (httpx.HTTPError, ValueError) as exc:
                                result = GeoResult(
                                    ip_address=ip_address,
                                    successful=False,
                                    failure_reason=str(exc)[:255],
                                )
                            store_result = True
                        if result.successful and (
                            result.latitude is None or result.longitude is None
                        ):
                            result = GeoResult(
                                ip_address=ip_address,
                                successful=False,
                                failure_reason="provider returned no coordinates",
                            )
                            store_result = True
                        if store_result:
                            await self._store_cache(session, result, cached, fetched_at=now)
                        batch_results[ip_address] = result
                    if result.successful:
                        self._apply(ioc, result)
                        stats["enriched"] += 1
                    else:
                        stats["failed"] += 1
                await session.commit()
        finally:
            if owns_client:
                await client.aclose()
        return stats

    @staticmethod
    async def _store_cache(
        session: AsyncSession,
        result: GeoResult,
        cached: GeoCache | None,
        *,
        fetched_at: datetime | None = None,
    ) -> None:
        entry = cached or GeoCache(ip_address=result.ip_address)
        entry.country = result.country
        entry.country_code = result.country_code
        entry.city = result.city
        entry.asn = result.asn
        entry.asn_org = result.asn_org
        entry.latitude = result.latitude
        entry.longitude = result.longitude
        entry.successful = result.successful
        entry.failure_reason = result.failure_reason
        entry.fetched_at = fetched_at or datetime.now(UTC)
        if cached is None:
            session.add(entry)

    @staticmethod
    def _apply(ioc: IOC, result: GeoResult) -> None:
        ioc.country = result.country
        ioc.country_code = result.country_code
        ioc.city = result.city
        ioc.asn = result.asn
        ioc.asn_org = result.asn_org
        ioc.latitude = result.latitude
        ioc.longitude = result.longitude
        if result.latitude is not None and result.longitude is not None:
            ioc.location = f"SRID=4326;POINT({result.longitude} {result.latitude})"


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _result_from_cache(cache: GeoCache) -> GeoResult:
    return GeoResult(
        ip_address=cache.ip_address,
        successful=cache.successful,
        country=cache.country,
        country_code=cache.country_code,
        city=cache.city,
        asn=cache.asn,
        asn_org=cache.asn_org,
        latitude=cache.latitude,
        longitude=cache.longitude,
        failure_reason=cache.failure_reason,
    )
