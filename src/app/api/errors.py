from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from app.core.config import get_settings

logger = structlog.get_logger()

PROBLEM_MEDIA_TYPE = "application/problem+json"

_STATUS_CODE_NAMES: dict[int, str] = {
    400: "MALFORMED_REQUEST",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    503: "SERVICE_UNAVAILABLE",
}


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def _problem_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    title: str,
    detail: str,
    errors: list[dict[str, Any]] | None = None,
) -> JSONResponse:
    settings = get_settings()
    body = {
        "type": f"{settings.base_url}/problems/{code}",
        "title": title,
        "status": status_code,
        "detail": detail,
        "instance": str(request.url.path),
        "code": code,
        "request_id": _request_id(request),
        "errors": errors or [],
    }
    return JSONResponse(status_code=status_code, content=body, media_type=PROBLEM_MEDIA_TYPE)


async def http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = _STATUS_CODE_NAMES.get(exc.status_code, "HTTP_ERROR")
    return _problem_response(
        request,
        status_code=exc.status_code,
        code=code,
        title="Request cannot be completed",
        detail=str(exc.detail),
    )


async def validation_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errors = [
        {"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]
    return _problem_response(
        request,
        status_code=422,
        code="VALIDATION_ERROR",
        title="Request body failed validation",
        detail="One or more fields failed validation.",
        errors=errors,
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    await logger.aexception("unhandled_exception", path=request.url.path)
    return _problem_response(
        request,
        status_code=500,
        code="INTERNAL_ERROR",
        title="An unexpected error occurred",
        detail="An unexpected error occurred. It has been logged for investigation.",
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
