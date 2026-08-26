from __future__ import annotations

from typing import Any

from app.ingestion.base import (
    FeedBatch,
    FeedConnector,
    FeedError,
    NormalizedIOC,
    canonicalize_indicator,
    infer_ioc_type,
    parse_datetime,
    split_ip_port,
)


class ThreatFoxConnector(FeedConnector):
    name = "threatfox"
    requires_auth = True

    @staticmethod
    def parse(payload: dict[str, Any]) -> list[NormalizedIOC]:
        return ThreatFoxConnector.parse_batch(payload).indicators

    @staticmethod
    def parse_batch(payload: dict[str, Any]) -> FeedBatch:
        if payload.get("query_status") not in {None, "ok"}:
            raise FeedError(f"ThreatFox returned {payload.get('query_status')}")
        if "data" not in payload or not isinstance(payload["data"], list):
            raise FeedError("ThreatFox response is missing the data record list")
        records = payload["data"]
        normalized: list[NormalizedIOC] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                ioc_type = infer_ioc_type(record["ioc"], record.get("ioc_type"))
                port = None
                value = record["ioc"]
                if ioc_type.value == "ip":
                    value, port = split_ip_port(value)
                seen = parse_datetime(record.get("first_seen"))
                last_seen = parse_datetime(record.get("last_seen"), fallback=seen)
                confidence = float(record.get("confidence_level") or 70)
                normalized.append(
                    NormalizedIOC(
                        ioc_value=canonicalize_indicator(value, ioc_type),
                        ioc_type=ioc_type,
                        port=port,
                        malware_family=record.get("malware_printable") or record.get("malware"),
                        first_seen=seen,
                        last_seen=max(seen, last_seen),
                        source_feed="threatfox",
                        confidence_hint=max(0, min(confidence, 100)),
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
        response = await self.request("POST", json={"query": "get_iocs", "days": 3})
        return self.parse_batch(response.json())
