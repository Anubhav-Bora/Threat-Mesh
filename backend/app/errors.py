from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class AppError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: Any | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def error_payload(request: Request, code: str, message: str, details: Any = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "error": {"code": code, "message": message},
        "request_id": getattr(request.state, "request_id", None),
    }
    if details is not None:
        payload["error"]["details"] = details
    return payload


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_payload(request, exc.code, exc.message, exc.details),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        details = [
            {
                "location": ".".join(str(part) for part in error["loc"]),
                "message": error["msg"],
                "type": error["type"],
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=error_payload(
                request, "validation_error", "Request validation failed", details
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled request error", extra={"request_id": request.state.request_id})
        message = str(exc) if app.debug else "An unexpected server error occurred"
        return JSONResponse(
            status_code=500,
            content=error_payload(request, "internal_error", message),
        )
