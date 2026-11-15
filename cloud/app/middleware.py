"""Pure-ASGI middleware: body buffering + HMAC auth (API.md §0) + X-Latency-Ms / X-Server-Time on every
response (incl. 401/404/413/500/503) + request metrics + access log without bodies (no images, ever).

- A declared Content-Length above MAX_BODY_BYTES is refused (413) before a single body byte is read.
- HMAC verification runs in a worker thread: the kiosk-key lookup reads the schedule and the replay guard writes
  to the KV store, both blocking calls that must never stall the event loop. A store outage is 503
  CLOUD_UNAVAILABLE (never a misleading 401) unless the last-good kiosk list still answers.
- An exception that escapes the app is turned into the 500 error envelope HERE, so it carries X-Server-Time and
  X-Latency-Ms like every other response (Starlette's outer error middleware would add neither).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time

from .auth import AuthFailure, verify_request
from .errors import error_body
from .services.kv import StoreUnavailable

log = logging.getLogger("hid.cloud.access")

PUBLIC_PATHS = {"/health", "/v1/health"}
# Idempotent by design (per-item conditional puts + per-item HMAC), so an identical re-sent request is
# harmless and must not be rejected as a replay (edge retries of a lost-ack batch, Y01).
REPLAY_EXEMPT = {"/v1/sync", "/v1/schedule/check"}
DOCS_PATHS = {"/docs", "/openapi.json", "/redoc", "/docs/oauth2-redirect"}
ROUTE_PREFIXES = ("/v1/match", "/v1/enroll", "/v1/schedule", "/v1/revocations", "/v1/sync", "/v1/otp",
                  "/v1/liveness", "/v1/admin", "/v1/health", "/health")


def route_label(path: str) -> str:
    for p in ROUTE_PREFIXES:
        if path == p or path.startswith(p + "/") or path.startswith(p + "?"):
            return p
    return "other"


class HidMiddleware:
    def __init__(self, app, *, get_services) -> None:
        self.app = app
        self.get_services = get_services

    async def _send_error(self, send, t0: float, status: int, code: str, message: str) -> None:
        body = json.dumps(error_body(code, message)).encode()
        await self._send_json(send, t0, status, body)

    @staticmethod
    async def _send_json(send, t0: float, status: int, body: bytes) -> None:
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-latency-ms", str(int((time.perf_counter() - t0) * 1000)).encode()),
            (b"x-server-time", str(int(time.time())).encode()),
        ]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        t0 = time.perf_counter()
        svc = self.get_services()
        s = svc.settings
        path, method = scope["path"], scope["method"]

        declared = _content_length(scope)
        if declared is not None and declared > s.max_body_bytes:
            return await self._send_error(send, t0, 413, "PAYLOAD_TOO_LARGE",
                                          f"body larger than {s.max_body_bytes} bytes")
        chunks: list[bytes] = []
        size = 0
        more = True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return None
            chunk = msg.get("body", b"")
            size += len(chunk)
            if size > s.max_body_bytes:
                return await self._send_error(send, t0, 413, "PAYLOAD_TOO_LARGE",
                                              f"body larger than {s.max_body_bytes} bytes")
            chunks.append(chunk)
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        kiosk_id = None
        public = path in PUBLIC_PATHS or (s.enable_docs and path in DOCS_PATHS)
        if not public:
            headers, repeated = _auth_headers(scope)
            if repeated:
                return await self._send_error(send, t0, 401, "UNAUTHORIZED",
                                              f"auth header {repeated} sent more than once")
            try:
                kiosk_id = await asyncio.to_thread(
                    verify_request,
                    headers=headers, method=method, path=path,
                    query_string=scope.get("query_string", b"").decode("latin-1"), body=body,
                    api_key=s.cloud_api_key,
                    # an explicit per-kiosk key needs no store read (a store outage must not stop those kiosks)
                    key_lookup=lambda k: s.kiosk_keys.get(k) or s.key_for_kiosk(k, svc.schedule.known_kiosks()),
                    skew_s=s.auth_skew_s, replay=None if path in REPLAY_EXEMPT else svc.replay,
                    accept_bare_path=s.accept_bare_path_sig)
            except AuthFailure as af:
                svc.metrics.count("AuthFailures", Route=route_label(path))
                log.info(json.dumps({"route": route_label(path), "method": method, "status": 401,
                                     "reason": af.message}))
                return await self._send_error(send, t0, 401, af.code, af.message)
            except Exception as exc:  # noqa: BLE001 - store outage (kiosk list / replay guard): never a guess
                svc.metrics.count("ServerErrors", Route=route_label(path))
                log.warning("kiosk auth not evaluated (%s)", type(exc).__name__,
                            exc_info=not isinstance(exc, StoreUnavailable))
                return await self._send_error(send, t0, 503, "CLOUD_UNAVAILABLE",
                                              "store unavailable; retry (kiosk authentication not evaluated)")
            scope["hid.kiosk_id"] = kiosk_id

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status_box = {"status": 500, "started": False}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_box["status"] = message["status"]
                status_box["started"] = True
                latency = str(int((time.perf_counter() - t0) * 1000)).encode()
                message = {**message, "headers": [*message.get("headers", []), (b"x-latency-ms", latency),
                                                  (b"x-server-time", str(int(time.time())).encode())]}
            await send(message)

        try:
            await self.app(scope, replay_receive, send_wrapper)
        except Exception as exc:  # noqa: BLE001 - the envelope is built here (X-Server-Time), never re-raised
            log.exception("unhandled error on %s %s: %s", method, route_label(path), type(exc).__name__)
            status_box["status"] = 500
            if not status_box["started"]:
                await self._send_error(send, t0, 500, "INTERNAL", "internal error")
        finally:
            ms = (time.perf_counter() - t0) * 1000
            label = route_label(path)
            svc.metrics.put("RequestLatencyMs", ms, Route=label)
            if status_box["status"] >= 500:
                svc.metrics.count("ServerErrors", Route=label)
            if label not in ("/v1/health", "/health"):
                log.info(json.dumps({"route": label, "method": method, "status": status_box["status"],
                                     "latency_ms": round(ms, 1), "kiosk_id": kiosk_id}))


def _content_length(scope) -> int | None:
    for k, v in scope.get("headers", []):
        if k.lower() == b"content-length":
            try:
                return int(v.decode("latin-1").strip())
            except ValueError:
                return None
    return None


_SIGNED_HEADERS = (b"x-kiosk-id", b"x-timestamp", b"x-signature", b"x-api-key")


def _auth_headers(scope) -> tuple[dict[str, str], str | None]:
    """Lower-cased headers (last value) + the name of a repeated kiosk-auth header, if any."""
    out: dict[str, str] = {}
    seen: set[bytes] = set()
    repeated = None
    for k, v in scope.get("headers", []):
        lk = k.lower()
        if lk in _SIGNED_HEADERS and lk in seen:
            repeated = lk.decode("latin-1")
        seen.add(lk)
        out[lk.decode("latin-1")] = v.decode("latin-1")
    return out, repeated
