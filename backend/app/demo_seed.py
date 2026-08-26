from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.attack_mapping import AttackMappingService
from app.clustering import ClusteringService
from app.config import Settings
from app.database import Database
from app.detection_rules import DetectionRuleService
from app.ingestion.base import indicator_key
from app.models import IOC, FeedRun, FeedRunStatus, IOCType, Report
from app.scoring import ConfidenceService

DEMO_IOCS: tuple[dict[str, Any], ...] = (
    {
        "value": "198.51.100.24",
        "type": IOCType.IP,
        "port": 443,
        "family": "Emotet",
        "source": "feodo",
        "country": "Germany",
        "code": "DE",
        "city": "Frankfurt",
        "asn": "AS64501",
        "org": "Example Transit Europe",
        "lat": 50.1109,
        "lon": 8.6821,
        "hours": 2,
    },
    {
        "value": "198.51.100.24",
        "type": IOCType.IP,
        "port": 443,
        "family": "Emotet",
        "source": "threatfox",
        "country": "Germany",
        "code": "DE",
        "city": "Frankfurt",
        "asn": "AS64501",
        "org": "Example Transit Europe",
        "lat": 50.1109,
        "lon": 8.6821,
        "hours": 3,
    },
    {
        "value": "198.51.100.37",
        "type": IOCType.IP,
        "port": 8080,
        "family": "Emotet",
        "source": "feodo",
        "country": "Netherlands",
        "code": "NL",
        "city": "Amsterdam",
        "asn": "AS64501",
        "org": "Example Transit Europe",
        "lat": 52.3676,
        "lon": 4.9041,
        "hours": 7,
    },
    {
        "value": "203.0.113.18",
        "type": IOCType.IP,
        "port": 8443,
        "family": "Cobalt Strike",
        "source": "threatfox",
        "country": "United States",
        "code": "US",
        "city": "Ashburn",
        "asn": "AS64502",
        "org": "Example Cloud North America",
        "lat": 39.0438,
        "lon": -77.4874,
        "hours": 10,
    },
    {
        "value": "203.0.113.28",
        "type": IOCType.IP,
        "port": 443,
        "family": "Cobalt Strike",
        "source": "threatfox",
        "country": "United States",
        "code": "US",
        "city": "Ashburn",
        "asn": "AS64502",
        "org": "Example Cloud North America",
        "lat": 39.0438,
        "lon": -77.4874,
        "hours": 14,
    },
    {
        "value": "192.0.2.44",
        "type": IOCType.IP,
        "port": 53,
        "family": "Mirai",
        "source": "feodo",
        "country": "Singapore",
        "code": "SG",
        "city": "Singapore",
        "asn": "AS64503",
        "org": "Example APAC Hosting",
        "lat": 1.3521,
        "lon": 103.8198,
        "hours": 20,
    },
    {
        "value": "192.0.2.59",
        "type": IOCType.IP,
        "port": 23,
        "family": "Mirai",
        "source": "feodo",
        "country": "Japan",
        "code": "JP",
        "city": "Tokyo",
        "asn": "AS64503",
        "org": "Example APAC Hosting",
        "lat": 35.6762,
        "lon": 139.6503,
        "hours": 25,
    },
    {
        "value": "198.51.100.88",
        "type": IOCType.IP,
        "port": 443,
        "family": "QakBot",
        "source": "threatfox",
        "country": "France",
        "code": "FR",
        "city": "Paris",
        "asn": "AS64504",
        "org": "Example Edge Services",
        "lat": 48.8566,
        "lon": 2.3522,
        "hours": 31,
    },
    {
        "value": "bad-example.test",
        "type": IOCType.DOMAIN,
        "family": "QakBot",
        "source": "threatfox",
        "hours": 32,
    },
    {
        "value": "https://payload.example.test/update.bin",
        "type": IOCType.URL,
        "family": "Emotet",
        "source": "urlhaus",
        "hours": 36,
    },
    {
        "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "type": IOCType.HASH,
        "family": "RedLine",
        "source": "threatfox",
        "hours": 42,
    },
    {
        "value": "203.0.113.77",
        "type": IOCType.IP,
        "port": 9001,
        "family": "AsyncRAT",
        "source": "threatfox",
        "country": "Brazil",
        "code": "BR",
        "city": "Sao Paulo",
        "asn": "AS64505",
        "org": "Example LATAM Network",
        "lat": -23.5505,
        "lon": -46.6333,
        "hours": 48,
    },
)


async def seed_demo(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    *,
    now: datetime | None = None,
) -> dict[str, int]:
    """Idempotently upsert clearly marked synthetic data and run deterministic analysis."""

    anchor = now or datetime.now(UTC)
    inserted = updated = 0
    async with session_factory() as session:
        for item in DEMO_IOCS:
            port = item.get("port")
            key = indicator_key(item["value"], item["type"], port)
            existing = await session.scalar(
                select(IOC).where(
                    IOC.ioc_type == item["type"],
                    IOC.indicator_key == key,
                    IOC.source_feed == item["source"],
                )
            )
            seen = anchor - timedelta(hours=item["hours"])
            data = {
                "ioc_value": item["value"],
                "indicator_key": key,
                "ioc_type": item["type"],
                "port": port,
                "malware_family": item["family"],
                "first_seen": seen - timedelta(hours=4),
                "last_seen": seen,
                "source_feed": item["source"],
                "is_demo": True,
                "country": item.get("country"),
                "country_code": item.get("code"),
                "city": item.get("city"),
                "asn": item.get("asn"),
                "asn_org": item.get("org"),
                "latitude": item.get("lat"),
                "longitude": item.get("lon"),
                "location": f"SRID=4326;POINT({item['lon']} {item['lat']})"
                if item.get("lat") is not None
                else None,
                "raw_json": {
                    "demo": True,
                    "note": "Synthetic documentation-only indicator; not a live IOC",
                },
            }
            if existing:
                # Never relabel a live observation as synthetic when a reviewer
                # runs the optional demo command against a populated database.
                if not existing.is_demo:
                    continue
                for field, value in data.items():
                    setattr(existing, field, value)
                updated += 1
            else:
                session.add(IOC(**data))
                inserted += 1
        await session.commit()
    await AttackMappingService(session_factory).map_indicators()
    await ConfidenceService(session_factory).recalculate()
    await ClusteringService(session_factory, settings).rebuild()
    await DetectionRuleService(session_factory).generate(minimum_confidence=0, limit=500)
    await _seed_demo_status_and_report(session_factory, anchor)
    return {"inserted": inserted, "updated": updated, "total_demo_rows": len(DEMO_IOCS)}


async def _seed_demo_status_and_report(
    session_factory: async_sessionmaker[AsyncSession], anchor: datetime
) -> None:
    async with session_factory() as session:
        for source in ("urlhaus", "threatfox", "feodo"):
            feed_name = f"demo-{source}"
            run = await session.scalar(select(FeedRun).where(FeedRun.feed_name == feed_name))
            source_count = sum(item["source"] == source for item in DEMO_IOCS)
            if run is None:
                run = FeedRun(feed_name=feed_name, status=FeedRunStatus.SUCCEEDED)
                session.add(run)
            run.status = FeedRunStatus.SUCCEEDED
            run.started_at = anchor - timedelta(seconds=5)
            run.completed_at = anchor
            run.received_count = source_count
            run.inserted_count = source_count
            run.updated_count = 0
            run.rejected_count = 0
            run.error = None

        report = await session.scalar(
            select(Report).where(Report.provider == "demo", Report.model == "synthetic-v1")
        )
        report_data = {
            "period_start": anchor - timedelta(days=7),
            "period_end": anchor,
            "title": "ThreatMesh Demo CTI Report — Synthetic Data",
            "report_text": (
                "## Executive Summary\n\n"
                "This offline demonstration contains synthetic infrastructure only. "
                "It illustrates deterministic aggregation, ATT&CK context, campaign leads, "
                "and review-gated detection content without calling an LLM.\n\n"
                "## Analyst Notice\n\n"
                "No indicator in this report is presented as a live threat. IP geolocation is "
                "approximate infrastructure context, campaign groupings are analytic leads, "
                "and every generated rule requires human review before use."
            ),
            "provider": "demo",
            "model": "synthetic-v1",
            "facts_json": {
                "synthetic": True,
                "analysis_scope": "demo",
                "included_provenance": "demo",
                "period_corpus_mode": "demo",
                "total_observations": len(DEMO_IOCS),
                "unique_indicator_count": len(
                    {
                        (
                            item["type"].value,
                            indicator_key(item["value"], item["type"], item.get("port")),
                        )
                        for item in DEMO_IOCS
                    }
                ),
                "network_calls": 0,
            },
            "is_demo": True,
            "created_at": anchor,
        }
        if report is None:
            session.add(Report(**report_data))
        else:
            for field, value in report_data.items():
                setattr(report, field, value)
        await session.commit()


async def _main() -> None:
    parser = argparse.ArgumentParser(description="Idempotently load synthetic ThreatMesh demo data")
    parser.add_argument("--database-url", help="Override DATABASE_URL for this command")
    args = parser.parse_args()
    settings = Settings(database_url=args.database_url) if args.database_url else Settings()
    database = Database(settings)
    try:
        if settings.auto_create_schema:
            await database.create_schema()
        result = await seed_demo(database.session_factory, settings)
        print(
            "ThreatMesh demo seed complete: "
            f"{result['inserted']} inserted, {result['updated']} updated."
        )
    finally:
        await database.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
