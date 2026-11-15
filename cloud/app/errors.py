"""Protocol error envelope (docs/API.md §0): {"error": {"code", "message", "reason"?}}.

`reason` (v1.4, docs/API.md §3.18.6) is a machine-readable sub-code for domain errors (e.g. UNKNOWN_ROLE,
ERASED_IN_BUNDLE, SCHEDULE_CONFLICT); the edge forwards it verbatim. Request-model 422s carry no reason. Cloud
errors carry no attempt_id.

These are transport/protocol errors, distinct from decision reason codes. Validation errors never echo
request input (bodies can carry base64 face images).
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("hid.cloud")

STATUS_BY_CODE = {
    "VALIDATION_ERROR": 422,
    "UNAUTHORIZED": 401,
    "FORBIDDEN": 403,
    "NOT_FOUND": 404,
    "ATTEMPT_NOT_FOUND": 404,
    "ATTEMPT_CLOSED": 409,
    "INVALID_STATE": 409,
    "REQUEST_TIMEOUT": 408,
    "NONCE_EXPIRED": 410,
    "NONCE_REUSED": 409,
    "PAYLOAD_TOO_LARGE": 413,
    "RATE_LIMITED": 429,
    "CLOUD_UNAVAILABLE": 503,
    "UPSTREAM_THROTTLED": 503,
    "INTERNAL": 500,
}


class ApiError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status: int | None = None,
        attempt_id: str | None = None,
        headers: dict[str, str] | None = None,
        reason: str | None = None,
        extra: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.reason = reason
        self.extra = dict(extra or {})
        self.status = status or STATUS_BY_CODE.get(code, 500)
        self.attempt_id = attempt_id
        self.headers = headers or {}


def error_body(code: str, message: str, attempt_id: str | None = None, reason: str | None = None,
               extra: dict[str, object] | None = None) -> dict:
    err: dict[str, object] = {"code": code, "message": message}
    if attempt_id:
        err["attempt_id"] = attempt_id
    if reason:
        err["reason"] = reason
    for k, v in (extra or {}).items():
        err.setdefault(k, v)
    return {"error": err}


# Starlette / FastAPI HTTPException status -> protocol error code (never INTERNAL for a client error)
HTTP_STATUS_CODES = {400: "VALIDATION_ERROR", 401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND",
                     405: "VALIDATION_ERROR", 408: "REQUEST_TIMEOUT", 409: "INVALID_STATE", 410: "NONCE_EXPIRED",
                     413: "PAYLOAD_TOO_LARGE", 415: "VALIDATION_ERROR", 422: "VALIDATION_ERROR",
                     429: "RATE_LIMITED", 503: "CLOUD_UNAVAILABLE"}


def code_for_status(status: int) -> str:
    if status in HTTP_STATUS_CODES:
        return HTTP_STATUS_CODES[status]
    return "VALIDATION_ERROR" if 400 <= status < 500 else "INTERNAL"


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(error_body(exc.code, exc.message, exc.attempt_id, exc.reason, exc.extra),
                            status_code=exc.status, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Only location + message: never the offending input (could be an image or a secret).
        parts = []
        for e in exc.errors()[:10]:
            loc = ".".join(str(p) for p in e.get("loc", ()) if p != "body")
            parts.append(f"{loc}: {e.get('msg', 'invalid')}")
        return JSONResponse(error_body("VALIDATION_ERROR", "; ".join(parts) or "invalid request"), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = code_for_status(exc.status_code)
        msg = exc.detail if isinstance(exc.detail, str) else "error"
        return JSONResponse(error_body(code, msg), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse(error_body("INTERNAL", "internal error"), status_code=500)
