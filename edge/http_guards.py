"""ASGI guards in front of the edge routes (audit F3 / F5).

* BodyLimitMiddleware: per-route request-body caps enforced BEFORE any parsing or spooling. A declared
  Content-Length above the cap is refused at once; a streamed body is counted chunk by chunk and cut off as soon
  as it passes the cap. Both answer 413 PAYLOAD_TOO_LARGE in the normal error envelope.
* OriginGuardMiddleware: a state-changing request (not GET / HEAD / OPTIONS) whose Origin header is present but
  not one of the configured kiosk origins gets 403 FORBIDDEN reason ORIGIN_NOT_ALLOWED (a foreign web page can
  still send a "simple" cross-origin POST; CORS only hides the response).
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any

from edge.errors import error_body

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

MB = 1024 * 1024
DEFAULT_BODY_MAX = 64 * 1024  # every JSON route
# (method, path regex, cap): multipart routes sized from their part limits in edge/app.py plus headroom
ROUTE_BODY_MAX: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("POST", re.compile(r"^/v1/attempt/[^/]+/frames$"), 12 * MB),  # <= 5 frames x 2 MB + meta
    ("POST", re.compile(r"^/v1/attempt/[^/]+/probe$"), 3 * MB),  # 1 probe x 2 MB
    ("POST", re.compile(r"^/v1/attempt/[^/]+/challenge$"), 7 * MB),  # <= 3 frames x 2 MB
    ("POST", re.compile(r"^/v1/enroll$"), 12 * MB),  # <= 5 frames x 2 MB
    ("POST", re.compile(r"^/v1/depth/frames$"), 30 * MB),  # <= 3 depth x 8 MB + 1 rgb x 2 MB
)
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def body_limit(method: str, path: str) -> int:
    for m, rx, cap in ROUTE_BODY_MAX:
        if m == method and rx.match(path):
            return cap
    return DEFAULT_BODY_MAX


class BodyTooLarge(Exception):
    pass


async def _send_error(send: Send, status: int, code: str, message: str, extra: dict[str, Any] | None = None) -> None:
    body = json.dumps(error_body(code, message, None, extra)).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                            (b"connection", b"close")]})
    await send({"type": "http.response.body", "body": body})


def _header(scope: Scope, name: bytes) -> str | None:
    for k, v in scope.get("headers") or []:
        if k.lower() == name:
            return v.decode("latin-1")
    return None


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        cap = body_limit(str(scope.get("method", "")).upper(), str(scope.get("path", "")))
        declared = _header(scope, b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > cap
            except ValueError:
                await _send_error(send, 400, "VALIDATION_ERROR", "invalid Content-Length")
                return
            if too_big:
                await _send_error(send, 413, "PAYLOAD_TOO_LARGE", f"request body larger than {cap} bytes",
                                  {"max_bytes": cap})
                return
        await self._counted(scope, receive, send, cap)

    async def _counted(self, scope: Scope, receive: Receive, send: Send, cap: int) -> None:
        """Count streamed bytes. Once past `cap` the app sees an exception from receive(); whatever response the
        app then produces (a parser 400/422, a 500) is replaced by the 413, so the cause stays visible."""
        state = {"seen": 0, "exceeded": False, "replaced": False}

        async def limited_receive() -> Message:
            msg = await receive()
            if msg.get("type") == "http.request":
                state["seen"] += len(msg.get("body") or b"")
                if state["seen"] > cap:
                    state["exceeded"] = True
                    raise BodyTooLarge
            return msg

        async def guarded_send(msg: Message) -> None:
            if not state["exceeded"]:
                await send(msg)
                return
            if msg.get("type") == "http.response.start" and not state["replaced"]:
                state["replaced"] = True
                await _send_error(send, 413, "PAYLOAD_TOO_LARGE", f"request body larger than {cap} bytes",
                                  {"max_bytes": cap})

        try:
            await self.app(scope, limited_receive, guarded_send)
        except BodyTooLarge:
            if not state["replaced"]:
                state["replaced"] = True
                await _send_error(send, 413, "PAYLOAD_TOO_LARGE", f"request body larger than {cap} bytes",
                                  {"max_bytes": cap})


class OriginGuardMiddleware:
    def __init__(self, app: ASGIApp, allowed_origins: Iterable[str]) -> None:
        self.app = app
        self.allowed = frozenset(o.rstrip("/") for o in allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http" and str(scope.get("method", "")).upper() not in SAFE_METHODS:
            origin = _header(scope, b"origin")
            if origin is not None and origin.rstrip("/") not in self.allowed:
                await _send_error(send, 403, "FORBIDDEN", "request origin is not an allowed kiosk origin",
                                  {"reason": "ORIGIN_NOT_ALLOWED"})
                return
        await self.app(scope, receive, send)
