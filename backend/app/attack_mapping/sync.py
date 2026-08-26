from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

import httpx

from app.attack_mapping.service import AttackMappingService
from app.config import Settings
from app.database import Database

ATTACK_VERSION = "19.2"
OFFICIAL_ENTERPRISE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"v{ATTACK_VERSION}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
MAX_BUNDLE_BYTES = 70 * 1024 * 1024


async def fetch_official_bundle(
    *,
    client: httpx.AsyncClient,
    url: str = OFFICIAL_ENTERPRISE_URL,
    max_bytes: int = MAX_BUNDLE_BYTES,
) -> dict[str, Any]:
    """Fetch the version-pinned official STIX 2.1 bundle with a hard size ceiling."""

    chunks: list[bytes] = []
    received = 0
    async with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
        response.raise_for_status()
        declared_size = int(response.headers.get("Content-Length", 0))
        if declared_size > max_bytes:
            raise ValueError(
                f"ATT&CK bundle declares {declared_size} bytes; limit is {max_bytes} bytes"
            )
        async for chunk in response.aiter_bytes():
            received += len(chunk)
            if received > max_bytes:
                raise ValueError(f"ATT&CK bundle exceeded the {max_bytes}-byte limit")
            chunks.append(chunk)
    payload = json.loads(b"".join(chunks))
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        raise ValueError("Downloaded file is not an ATT&CK STIX bundle")
    return payload


async def _main() -> None:
    parser = argparse.ArgumentParser(
        description=f"Load official Enterprise ATT&CK STIX 2.1 v{ATTACK_VERSION}"
    )
    parser.add_argument(
        "--file",
        type=Path,
        help="Load an already-downloaded bundle instead of accessing GitHub",
    )
    args = parser.parse_args()
    settings = Settings()
    database = Database(settings)
    try:
        service = AttackMappingService(database.session_factory)
        if args.file:
            result = await service.load_stix_file(args.file)
            source = str(args.file)
        else:
            timeout = httpx.Timeout(settings.http_timeout_seconds, connect=10.0)
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                headers={"User-Agent": settings.http_user_agent},
            ) as client:
                payload = await fetch_official_bundle(client=client)
            result = await service.load_stix_payload(payload)
            source = OFFICIAL_ENTERPRISE_URL
        print(f"Loaded {result['loaded']} active ATT&CK techniques from {source}")
    finally:
        await database.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
