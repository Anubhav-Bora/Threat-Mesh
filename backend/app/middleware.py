from __future__ import annotations

import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


class SecurityAndObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = request.headers.get("X-Request-ID", "")[:128] or str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path in {"/docs", "/redoc", "/openapi.json"}:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )
        logger.info(
            "request_complete",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response


class SlidingWindowRateLimiter:
    """Small in-process limiter suitable for one instance; use Redis at larger scale."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, limit: int, period_seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        events = self._events[key]
        cutoff = now - period_seconds
        while events and events[0] <= cutoff:
            events.popleft()
        if len(events) >= limit:
            retry_after = max(1, int(period_seconds - (now - events[0])))
            return False, retry_after
        events.append(now)
        if len(self._events) > 10_000:
            stale_keys = [
                candidate
                for candidate, values in self._events.items()
                if not values or values[-1] <= cutoff
            ]
            for candidate in stale_keys:
                self._events.pop(candidate, None)
        return True, 0


class PublicRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: object, limiter: SlidingWindowRateLimiter, limit: int) -> None:
        super().__init__(app)
        self.limiter = limiter
        self.limit = limit

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in {"/health", "/ready"}:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        allowed, retry_after = self.limiter.check(f"public:{client}", self.limit)
        if not allowed:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": "Too many requests; retry later",
                    },
                    "request_id": getattr(request.state, "request_id", None),
                },
            )
        return await call_next(request)
