from __future__ import annotations

from typing import Any

from app.ingestion.base import (
    FeedBatch,
    FeedConnector,
    FeedError,
    NormalizedIOC,
    canonicalize_indicator,
    parse_datetime,
)
from app.models.enums import IOCType


class URLhausConnector(FeedConnector):
    name = "urlhaus"
    requires_auth = True

    @staticmethod
    def parse(payload: dict[str, Any]) -> list[NormalizedIOC]:
        return URLhausConnector.parse_batch(payload).indicators

    @staticmethod
    def parse_batch(payload: dict[str, Any]) -> FeedBatch:
        if "urls" in payload:
            records = payload["urls"]
        elif "data" in payload:
            records = payload["data"]
        else:
            raise FeedError("URLhaus response is missing the urls/data record list")
        if not isinstance(records, list):
            raise FeedError("URLhaus records must be a list")
        normalized: list[NormalizedIOC] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                seen = parse_datetime(record.get("date_added") or record.get("first_seen"))
                last_seen = parse_datetime(record.get("last_online"), fallback=seen)
                tags = record.get("tags") or []
                if isinstance(tags, str):
                    tags = [tag.strip() for tag in tags.split(",")]
                elif isinstance(tags, list):
                    tags = [tag for tag in tags if isinstance(tag, str)]
                else:
                    tags = []
                family = record.get("malware_family") or next(
                    (tag for tag in tags if tag and tag.lower() not in {"exe", "elf", "zip"}),
                    None,
                )
                normalized.append(
                    NormalizedIOC(
                        ioc_value=canonicalize_indicator(record["url"], IOCType.URL),
                        ioc_type=IOCType.URL,
                        malware_family=family or record.get("threat"),
                        first_seen=seen,
                        last_seen=max(seen, last_seen),
                        source_feed="urlhaus",
                        confidence_hint=65.0,
                        raw_json=record,
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return FeedBatch(
            indicators=normalized,
            attempted=len(records),
            rejected=len(records) - len(normalized),
        )

    async def fetch(self) -> FeedBatch:
        response = await self.request()
        return self.parse_batch(response.json())
