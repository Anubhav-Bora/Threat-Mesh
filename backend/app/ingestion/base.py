from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import IOCType

logger = logging.getLogger(__name__)

# Feed clocks occasionally drift slightly; anything beyond this allowance is treated
# as invalid upstream data rather than a maximally recent observation.
MAX_FUTURE_CLOCK_SKEW = timedelta(minutes=10)


class FeedError(RuntimeError):
    pass


class NormalizedIOC(BaseModel):
    model_config = ConfigDict(frozen=True)

    ioc_value: str = Field(min_length=1, max_length=2048)
    ioc_type: IOCType
    port: int | None = Field(default=None, ge=1, le=65535)
    malware_family: str | None = Field(default=None, max_length=255)
    first_seen: datetime
    last_seen: datetime
    source_feed: str = Field(min_length=1, max_length=64)
    confidence_hint: float = Field(default=50.0, ge=0, le=100)
    raw_json: dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class FeedBatch:
    indicators: list[NormalizedIOC]
    attempted: int
    rejected: int

    def __post_init__(self) -> None:
        if (
            self.attempted < 0
            or self.rejected < 0
            or len(self.indicators) + self.rejected != self.attempted
        ):
            raise ValueError("invalid feed batch counters")


def parse_datetime(
    value: Any,
    *,
    fallback: datetime | None = None,
    now: datetime | None = None,
) -> datetime:
    if value is None or value == "":
        if fallback is not None:
            return fallback
        raise ValueError("missing feed timestamp")
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(value, tz=UTC)
        except (OSError, OverflowError, ValueError) as exc:
            raise ValueError("invalid feed timestamp") from exc
    else:
        text = str(value).strip().replace("Z", "+00:00")
        formats = (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
            "%d.%m.%Y %H:%M:%S",
        )
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            for date_format in formats:
                try:
                    parsed = datetime.strptime(text, date_format)
                    break
                except ValueError:
                    continue
            else:
                logger.debug("Could not parse feed timestamp %r", value)
                raise ValueError("invalid feed timestamp")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    current = now or datetime.now(UTC)
    current = current.replace(tzinfo=UTC) if current.tzinfo is None else current.astimezone(UTC)
    if parsed > current + MAX_FUTURE_CLOCK_SKEW:
        raise ValueError("feed timestamp exceeds the 10-minute future clock-skew allowance")
    return parsed


def canonicalize_indicator(value: str, ioc_type: IOCType) -> str:
    value = value.strip()
    if ioc_type is IOCType.IP:
        address, _ = split_ip_port(value)
        return address
    if ioc_type is IOCType.DOMAIN:
        domain = value.rstrip(".").lower()
        if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)[a-z0-9_.-]+", domain):
            raise ValueError("invalid domain indicator")
        return domain
    if ioc_type is IOCType.URL:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("invalid URL indicator")
        host = parsed.hostname.lower()
        try:
            port = f":{parsed.port}" if parsed.port else ""
        except ValueError as exc:
            raise ValueError("invalid URL port") from exc
        bracketed_host = f"[{host}]" if ":" in host else host
        userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
        netloc = userinfo + bracketed_host + port
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
    if ioc_type is IOCType.HASH:
        normalized = value.lower()
        if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}", normalized):
            raise ValueError("invalid hash indicator")
        return normalized
    raise ValueError(f"unsupported IOC type: {ioc_type}")


def split_ip_port(value: str, explicit_port: Any = None) -> tuple[str, int | None]:
    candidate = value.strip()
    parsed_port: int | None = None
    if candidate.startswith("[") and "]" in candidate:
        closing = candidate.index("]")
        host = candidate[1:closing]
        suffix = candidate[closing + 1 :]
        if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
            raise ValueError("invalid bracketed IP address or port")
        if suffix:
            parsed_port = int(suffix[1:])
        candidate = host
    elif candidate.count(":") == 1:
        host, suffix = candidate.rsplit(":", 1)
        if suffix.isdigit():
            candidate = host
            parsed_port = int(suffix)
    if explicit_port not in {None, ""}:
        parsed_port = int(explicit_port)
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise ValueError("invalid network port")
    return str(ipaddress.ip_address(candidate)), parsed_port


def indicator_key(value: str, ioc_type: IOCType, port: int | None = None) -> str:
    if ioc_type is IOCType.IP and port:
        address = ipaddress.ip_address(value)
        host = f"[{address}]" if address.version == 6 else str(address)
        return f"{host}:{port}"
    return value


def infer_ioc_type(value: str, source_type: str | None = None) -> IOCType:
    normalized_type = (source_type or "").lower().replace("_", "-")
    if normalized_type in {"ip", "ip:port", "ipv4", "ipv6", "ip-port"}:
        return IOCType.IP
    if "url" in normalized_type:
        return IOCType.URL
    if normalized_type in {"domain", "hostname", "host"}:
        return IOCType.DOMAIN
    if "hash" in normalized_type or normalized_type in {"md5", "sha1", "sha256"}:
        return IOCType.HASH
    try:
        split_ip_port(value)
        return IOCType.IP
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return IOCType.URL
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return IOCType.HASH
    return IOCType.DOMAIN


class FeedConnector(ABC):
    name: str
    requires_auth: bool = False

    def __init__(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        auth_key: str | None = None,
        max_response_bytes: int = 8_388_608,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.client = client
        self.url = url
        self.auth_key = auth_key
        self.max_response_bytes = max_response_bytes

    @property
    def headers(self) -> dict[str, str]:
        return {"Auth-Key": self.auth_key} if self.auth_key else {}

    async def request(self, method: str = "GET", **kwargs: Any) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                async with self.client.stream(
                    method,
                    self.url,
                    headers=self.headers,
                    follow_redirects=False,
                    **kwargs,
                ) as response:
                    response.raise_for_status()
                    declared_length = response.headers.get("Content-Length")
                    if declared_length is not None:
                        try:
                            parsed_length = int(declared_length)
                        except ValueError as exc:
                            raise FeedError(
                                f"{self.name} returned an invalid Content-Length"
                            ) from exc
                        if parsed_length < 0:
                            raise FeedError(f"{self.name} returned an invalid Content-Length")
                        if parsed_length > self.max_response_bytes:
                            raise FeedError(
                                f"{self.name} response exceeds the configured "
                                f"{self.max_response_bytes}-byte limit"
                            )

                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(content) + len(chunk) > self.max_response_bytes:
                            raise FeedError(
                                f"{self.name} response exceeds the configured "
                                f"{self.max_response_bytes}-byte limit"
                            )
                        content.extend(chunk)
                    # ``aiter_bytes`` yields the decoded representation. Reusing the
                    # upstream encoding metadata would make the reconstructed response
                    # attempt to decode the already-decoded body a second time.
                    decoded_headers = [
                        (key, value)
                        for key, value in response.headers.multi_items()
                        if key.lower() not in {"content-encoding", "content-length"}
                    ]
                    return httpx.Response(
                        response.status_code,
                        headers=decoded_headers,
                        content=bytes(content),
                        request=response.request,
                    )
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_error = exc
                if attempt < 2:
                    await asyncio.sleep(0.4 * (2**attempt))
        raise FeedError(f"{self.name} request failed after retries: {last_error}")

    @abstractmethod
    async def fetch(self) -> FeedBatch:
        raise NotImplementedError
