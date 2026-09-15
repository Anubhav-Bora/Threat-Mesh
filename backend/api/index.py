from __future__ import annotations

import base64
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx


def _apply_vercel_defaults() -> None:
    import os

    os.environ.setdefault("SCHEDULER_ENABLED", "false")
    os.environ.setdefault("EXTERNAL_SCHEDULER_ENABLED", "false")


_apply_vercel_defaults()


def _ensure_import_path() -> None:
    backend_root = Path(__file__).resolve().parent.parent
    backend_root_str = str(backend_root)
    if backend_root_str not in sys.path:
        sys.path.insert(0, backend_root_str)


_ensure_import_path()

# Import after default env injection so startup settings pick up Vercel-safe defaults.
from app.main import app as fastapi_app  # noqa: E402


def _extract_headers(event: Mapping[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    event_headers = event.get("headers")
    if not isinstance(event_headers, Mapping):
        return headers
    for key, value in event_headers.items():
        if value is None:
            continue
        if isinstance(value, list):
            value = value[0] if value else ""
        headers[str(key)] = str(value)
    return headers


def _extract_query(event: Mapping[str, Any]) -> str:
    pairs: list[tuple[str, str]] = []

    multi = event.get("multiValueQueryStringParameters")
    if isinstance(multi, Mapping):
        for key, value in multi.items():
            if value is None:
                continue
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
                for item in value:
                    if item is None:
                        continue
                    pairs.append((str(key), str(item)))
            else:
                pairs.append((str(key), str(value)))

    single = event.get("queryStringParameters")
    if isinstance(single, Mapping):
        for key, value in single.items():
            if value is None:
                continue
            if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
                continue
            pairs.append((str(key), str(value)))

    return urlencode(pairs)


def _normalize_path(raw_path: str | None) -> str:
    path = (raw_path or "").strip()
    if not path:
        return "/"
    path = path.replace("/backend/api/index.py", "", 1) if path.startswith("/backend/api/index.py") else path
    path = path.replace("/backend/api/index", "", 1) if path.startswith("/backend/api/index") else path
    if path.startswith("/api/index.py"):
        path = path[len("/api/index.py") :]
    if path.startswith("/api/index"):
        path = path[len("/api/index") :]
    if not path:
        return "/"
    if not path.startswith("/"):
        return f"/{path}"
    return path


async def handler(event: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:  # noqa: ARG001
    method = str(event.get("httpMethod") or event.get("method") or "GET").upper()
    path = _normalize_path(str(event.get("path") or event.get("rawPath") or "/"))
    query = _extract_query(event)
    url = f"{path}?{query}" if query else path

    body = event.get("body")
    if event.get("isBase64Encoded") and isinstance(body, str):
        request_body = base64.b64decode(body)
    elif body is None:
        request_body = b""
    elif isinstance(body, str):
        request_body = body.encode("utf-8")
    else:
        request_body = bytes(body)

    headers = _extract_headers(event)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fastapi_app, lifespan="on"),
        base_url="http://localhost",
    ) as client:
        response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=request_body,
        )

    return {
        "statusCode": response.status_code,
        "headers": dict(response.headers),
        "body": response.text,
        "isBase64Encoded": False,
    }


app = fastapi_app
