from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import httpx
import pytest
from sqlalchemy import func, select

from app.ingestion.base import (
    FeedBatch,
    FeedError,
    NormalizedIOC,
    canonicalize_indicator,
    infer_ioc_type,
    parse_datetime,
    split_ip_port,
)
from app.ingestion.feodo import FeodoConnector
from app.ingestion.service import IngestionService
from app.ingestion.threatfox import ThreatFoxConnector
from app.ingestion.urlhaus import URLhausConnector
from app.models import IOC, FeedRun, FeedRunStatus, IOCType


def test_feed_parsers_normalize_and_preserve_ports() -> None:
    threatfox = ThreatFoxConnector.parse(
        {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "8.8.8.8:8443",
                    "ioc_type": "ip:port",
                    "malware_printable": "Cobalt Strike",
                    "first_seen": "2026-08-20 12:00:00",
                    "confidence_level": 90,
                }
            ],
        }
    )
    assert threatfox[0].ioc_value == "8.8.8.8"
    assert threatfox[0].port == 8443
    assert threatfox[0].ioc_type is IOCType.IP

    feodo = FeodoConnector.parse(
        [
            {
                "ip_address": "1.1.1.1",
                "port": "443",
                "first_seen": "2026-08-20",
                "malware": "Emotet",
            }
        ]
    )
    assert feodo[0].port == 443

    urlhaus = URLhausConnector.parse(
        {
            "urls": [
                {
                    "url": "HTTPS://Example.TEST/dropper#ignored",
                    "date_added": "2026-08-20 12:00:00",
                    "tags": ["emotet", "exe"],
                }
            ]
        }
    )
    assert urlhaus[0].ioc_value == "https://example.test/dropper"
    assert urlhaus[0].malware_family == "emotet"


def test_split_ip_port_handles_ipv6() -> None:
    assert split_ip_port("[2001:4860:4860::8888]:53") == ("2001:4860:4860::8888", 53)
    with pytest.raises(ValueError):
        split_ip_port("8.8.8.8:99999")
    with pytest.raises(ValueError):
        split_ip_port("[2001:4860:4860::8888]:not-a-port")


def test_url_canonicalization_preserves_ipv6_authority() -> None:
    value = canonicalize_indicator(
        "HTTP://user:p%40ss@[2001:db8::1]:8080/x?y=1#ignored", IOCType.URL
    )
    assert value == "http://user:p%40ss@[2001:db8::1]:8080/x?y=1"
    assert infer_ioc_type("2001:4860:4860::8888") is IOCType.IP
    assert infer_ioc_type("[2001:4860:4860::8888]:53") is IOCType.IP


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (
            ThreatFoxConnector.parse,
            {
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "8.8.8.8:443",
                        "ioc_type": "ip:port",
                        "first_seen": "definitely-not-a-date",
                    }
                ],
            },
        ),
        (
            URLhausConnector.parse,
            {"urls": [{"url": "https://example.test/x", "date_added": "not-a-date"}]},
        ),
        (
            FeodoConnector.parse,
            [{"ip_address": "1.1.1.1", "port": 443, "first_seen": "not-a-date"}],
        ),
    ],
)
def test_connectors_reject_malformed_nonempty_timestamps(parser, payload) -> None:
    assert parser(payload) == []
    with pytest.raises(ValueError, match="timestamp"):
        parse_datetime("not-a-date")


def test_feed_timestamp_rejects_excessive_future_clock_skew() -> None:
    now = datetime.now(UTC)
    assert parse_datetime(now + timedelta(minutes=10), now=now) == now + timedelta(minutes=10)
    with pytest.raises(ValueError, match="clock-skew"):
        parse_datetime(now + timedelta(minutes=10, seconds=1), now=now)
    future_batch = ThreatFoxConnector.parse_batch(
        {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "8.8.8.8:443",
                    "ioc_type": "ip:port",
                    "first_seen": (now + timedelta(days=1)).isoformat(),
                }
            ],
        }
    )
    assert future_batch.attempted == 1
    assert future_batch.rejected == 1
    assert future_batch.indicators == []


def test_connector_batch_counts_mixed_normalization_and_schema_drift() -> None:
    mixed = ThreatFoxConnector.parse_batch(
        {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "8.8.8.8:443",
                    "ioc_type": "ip:port",
                    "first_seen": "2026-08-20 12:00:00",
                },
                {
                    "ioc": "not an indicator",
                    "ioc_type": "ip:port",
                    "first_seen": "not-a-date",
                },
            ],
        }
    )
    assert (mixed.attempted, mixed.rejected, len(mixed.indicators)) == (2, 1, 1)
    with pytest.raises(FeedError, match="data record list"):
        ThreatFoxConnector.parse_batch({"query_status": "ok", "unexpected": []})


def test_connector_batches_reject_non_mapping_rows_and_bad_tags() -> None:
    urlhaus = URLhausConnector.parse_batch(
        {
            "urls": [
                {
                    "url": "https://example.test/x",
                    "date_added": "2026-08-20 12:00:00",
                    "tags": [123, "Emotet"],
                },
                "schema-drift",
            ]
        }
    )
    threatfox = ThreatFoxConnector.parse_batch(
        {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "8.8.8.8:443",
                    "ioc_type": "ip:port",
                    "first_seen": "2026-08-20 12:00:00",
                },
                42,
            ],
        }
    )
    feodo = FeodoConnector.parse_batch(
        [
            {
                "ip_address": "1.1.1.1",
                "port": 443,
                "first_seen": "2026-08-20 12:00:00",
            },
            ["not", "a", "record"],
        ]
    )
    assert urlhaus.indicators[0].malware_family == "Emotet"
    assert {(batch.attempted, batch.rejected) for batch in (urlhaus, threatfox, feodo)} == {(2, 1)}


@pytest.mark.asyncio
async def test_missing_auth_skips_feed_without_network(app, settings) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise AssertionError("network should not be called")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        connector = URLhausConnector(http, settings.urlhaus_url)
        result = await IngestionService(
            app.state.database.session_factory,
            settings,
            client=http,
            connectors=[connector],
        ).sync_all()
    assert result["skipped"] == 1
    assert result["failed"] == 0
    assert calls == 0


@pytest.mark.asyncio
async def test_auth_key_is_not_forwarded_across_redirects(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://redirect.invalid/steal"},
            request=request,
        )

    monkeypatch.setattr("app.ingestion.base.asyncio.sleep", AsyncMock())
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler), follow_redirects=True
    ) as client:
        connector = URLhausConnector(
            client, "https://urlhaus-api.abuse.ch/v1/urls/recent/", auth_key="secret"
        )
        with pytest.raises(FeedError, match="after retries"):
            await connector.request()

    assert len(requests) == 3
    assert all(request.url.host == "urlhaus-api.abuse.ch" for request in requests)
    assert all(request.headers.get("Auth-Key") == "secret" for request in requests)


class FakeConnector:
    name = "test-feed"
    requires_auth = False
    auth_key = None

    async def fetch(self) -> list[NormalizedIOC]:
        now = datetime.now(UTC)
        indicator = NormalizedIOC(
            ioc_value="8.8.4.4",
            ioc_type=IOCType.IP,
            port=53,
            malware_family="Emotet",
            first_seen=now,
            last_seen=now,
            source_feed=self.name,
            raw_json={"port": 53},
        )
        return [indicator, indicator]


class BatchConnector:
    requires_auth = False
    auth_key = None

    def __init__(self, name: str, batch: FeedBatch) -> None:
        self.name = name
        self.batch = batch

    async def fetch(self) -> FeedBatch:
        return self.batch


class ChunkedBody(httpx.AsyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_feed_response_limit_rejects_declared_and_streamed_overflow() -> None:
    unread_body = ChunkedBody(b"should-not-be-read")

    def declared_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Length": "100"},
            stream=unread_body,
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(declared_handler)) as client:
        connector = FeodoConnector(client, "https://feed.invalid/data", max_response_bytes=10)
        with pytest.raises(FeedError, match="10-byte limit"):
            await connector.request()
    assert unread_body.closed is True

    chunked_body = ChunkedBody(b"123456", b"78901", b"unread")

    def chunked_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=chunked_body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(chunked_handler)) as client:
        connector = FeodoConnector(client, "https://feed.invalid/data", max_response_bytes=10)
        with pytest.raises(FeedError, match="10-byte limit"):
            await connector.request()
    assert chunked_body.closed is True


@pytest.mark.asyncio
async def test_feed_upsert_is_idempotent(app, settings) -> None:
    service = IngestionService(
        app.state.database.session_factory, settings, connectors=[FakeConnector()]
    )
    first = await service.sync_all()
    second = await service.sync_all()
    assert first["inserted"] == 1
    assert first["feeds"][0]["rejected"] == 1
    assert second["updated"] == 1
    async with app.state.database.session_factory() as session:
        assert await session.scalar(select(func.count(IOC.id))) == 1
        ioc = await session.scalar(select(IOC))
        assert ioc.port == 53
        assert ioc.indicator_key == "8.8.4.4:53"
        assert ioc.is_demo is False


@pytest.mark.asyncio
async def test_feed_identity_includes_declared_ioc_type(app, settings) -> None:
    now = datetime.now(UTC)
    lexical_value = "deadbeefdeadbeefdeadbeefdeadbeef"
    batch = FeedBatch(
        indicators=[
            NormalizedIOC(
                ioc_value=lexical_value,
                ioc_type=ioc_type,
                port=None,
                first_seen=now - timedelta(hours=1),
                last_seen=now,
                source_feed="typed-feed",
            )
            for ioc_type in (IOCType.DOMAIN, IOCType.HASH)
        ],
        attempted=2,
        rejected=0,
    )
    service = IngestionService(
        app.state.database.session_factory,
        settings,
        connectors=[BatchConnector("typed-feed", batch)],
    )
    first = await service.sync_all()
    second = await service.sync_all()
    assert (first["inserted"], second["updated"]) == (2, 2)
    async with app.state.database.session_factory() as session:
        rows = list((await session.scalars(select(IOC))).all())
    assert {row.ioc_type for row in rows} == {IOCType.DOMAIN, IOCType.HASH}
    assert {row.indicator_key for row in rows} == {lexical_value}


@pytest.mark.asyncio
async def test_sync_persists_partial_and_all_invalid_feed_telemetry(app, settings) -> None:
    now = datetime.now(UTC)
    indicator = NormalizedIOC(
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IP,
        port=443,
        first_seen=now - timedelta(hours=1),
        last_seen=now,
        source_feed="mixed-feed",
    )
    mixed_service = IngestionService(
        app.state.database.session_factory,
        settings,
        connectors=[
            BatchConnector(
                "mixed-feed",
                FeedBatch(indicators=[indicator], attempted=2, rejected=1),
            )
        ],
    )
    mixed = await mixed_service.sync_all()
    assert mixed["failed"] == 0
    assert mixed["feeds"][0]["status"] == FeedRunStatus.PARTIAL
    assert (mixed["feeds"][0]["received"], mixed["feeds"][0]["rejected"]) == (2, 1)

    invalid_service = IngestionService(
        app.state.database.session_factory,
        settings,
        connectors=[
            BatchConnector("invalid-feed", FeedBatch(indicators=[], attempted=3, rejected=3))
        ],
    )
    invalid = await invalid_service.sync_all()
    assert invalid["failed"] == 1
    assert invalid["feeds"][0]["status"] == FeedRunStatus.FAILED
    assert (invalid["feeds"][0]["received"], invalid["feeds"][0]["rejected"]) == (3, 3)
    assert "all 3" in invalid["feeds"][0]["error"]

    async with app.state.database.session_factory() as session:
        runs = {run.feed_name: run for run in (await session.scalars(select(FeedRun))).all()}
    assert runs["mixed-feed"].status is FeedRunStatus.PARTIAL
    assert runs["mixed-feed"].received_count == 2
    assert runs["mixed-feed"].rejected_count == 1
    assert runs["invalid-feed"].status is FeedRunStatus.FAILED
    assert runs["invalid-feed"].received_count == 3
    assert runs["invalid-feed"].rejected_count == 3
