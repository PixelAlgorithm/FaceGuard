"""Protocol errors: {"error": {"code", "message", "attempt_id"}} (docs/API.md 0). Not reason codes."""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

STATUS = {
    "VALIDATION_ERROR": 422, "UNAUTHORIZED": 401, "FORBIDDEN": 403, "ATTEMPT_NOT_FOUND": 404,
    "NOT_FOUND": 404, "ATTEMPT_CLOSED": 409, "INVALID_STATE": 409, "NONCE_EXPIRED": 410,
    "NONCE_REUSED": 409, "NONCE_INVALID": 409, "PAYLOAD_TOO_LARGE": 413, "RATE_LIMITED": 429,
    "CLOUD_UNAVAILABLE": 503,
    "UPSTREAM_THROTTLED": 503, "MODELS_UNAVAILABLE": 503, "INTERNAL": 500,
}


class ApiError(Exception):
    """`extra` = additive machine-readable keys inside the error object (e.g. retry_after_s, reason)."""

    def __init__(self, code: str, message: str, attempt_id: str | None = None, status: int | None = None,
                 extra: dict | None = None, headers: dict[str, str] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.attempt_id = attempt_id
        self.status = status or STATUS.get(code, 400)
        self.extra = extra or {}
        self.headers = headers


def error_body(code: str, message: str, attempt_id: str | None = None, extra: dict | None = None) -> dict:
    return {"error": {**(extra or {}), "code": code, "message": message, "attempt_id": attempt_id}}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(error_body(exc.code, exc.message, exc.attempt_id, exc.extra), status_code=exc.status,
                            headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        errs = [{"loc": list(e.get("loc", [])), "msg": e.get("msg", "")} for e in exc.errors()][:10]
        return JSONResponse(
            {"error": {"code": "VALIDATION_ERROR", "message": "invalid request", "attempt_id": None,
                       "details": errs}},
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {401: "UNAUTHORIZED", 403: "FORBIDDEN", 404: "NOT_FOUND", 405: "VALIDATION_ERROR"}.get(
            exc.status_code, "INTERNAL" if exc.status_code >= 500 else "VALIDATION_ERROR"
        )
        return JSONResponse(error_body(code, str(exc.detail)), status_code=exc.status_code)
