from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.ingestion.base import indicator_key
from app.models import IOC, IOCType


def make_ioc(
    *,
    value: str = "8.8.8.8",
    ioc_type: IOCType = IOCType.IP,
    port: int | None = 443,
    family: str | None = "Emotet",
    source: str = "threatfox",
    hours_old: int = 1,
    **kwargs,
) -> IOC:
    now = datetime.now(UTC)
    return IOC(
        ioc_value=value,
        indicator_key=indicator_key(value, ioc_type, port),
        ioc_type=ioc_type,
        port=port,
        malware_family=family,
        source_feed=source,
        first_seen=now - timedelta(hours=hours_old + 2),
        last_seen=now - timedelta(hours=hours_old),
        raw_json={"test": True},
        **kwargs,
    )
