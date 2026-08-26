from __future__ import annotations

import csv
import io
from typing import Any

from app.ingestion.base import (
    FeedBatch,
    FeedConnector,
    FeedError,
    NormalizedIOC,
    parse_datetime,
    split_ip_port,
)
from app.models.enums import IOCType


class FeodoConnector(FeedConnector):
    name = "feodo"

    @staticmethod
    def parse(records: list[dict[str, Any]]) -> list[NormalizedIOC]:
        return FeodoConnector.parse_batch(records).indicators

    @staticmethod
    def parse_batch(records: list[dict[str, Any]]) -> FeedBatch:
        if not isinstance(records, list):
            raise FeedError("Feodo records must be a list")
        normalized: list[NormalizedIOC] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                value = record.get("ip_address") or record.get("dst_ip") or record["ip"]
                value, port = split_ip_port(value, record.get("port") or record.get("dst_port"))
                seen = parse_datetime(record.get("first_seen"))
                last_seen = parse_datetime(
                    record.get("last_online") or record.get("last_seen"), fallback=seen
                )
                family = record.get("malware") or record.get("malware_family") or "botnet-c2"
                normalized.append(
                    NormalizedIOC(
                        ioc_value=value,
                        ioc_type=IOCType.IP,
                        port=port,
                        malware_family=family,
                        first_seen=seen,
                        last_seen=max(seen, last_seen),
                        source_feed="feodo",
                        confidence_hint=85.0,
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
        try:
            payload = response.json()
            if isinstance(payload, list):
                records = payload
            elif isinstance(payload, dict) and "data" in payload:
                records = payload["data"]
            else:
                raise FeedError("Feodo response is missing the data record list")
        except ValueError:
            lines = [line for line in response.text.splitlines() if not line.startswith("#")]
            records = list(csv.DictReader(io.StringIO("\n".join(lines))))
        return self.parse_batch(records)
