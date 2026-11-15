"""Pure-ASGI middleware: body buffering + HMAC auth (API.md §0) + X-Latency-Ms / X-Server-Time on every
response (incl. 401/404/413) + request metrics + access log without bodies (no images, ever)."""

from __future__ import annotations

import json
import logging
import time

from .auth import AuthFailure, verify_request
from .errors import error_body

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
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
            try:
                kiosk_id = verify_request(
                    headers=headers, method=method, path=path,
                    query_string=scope.get("query_string", b"").decode("latin-1"), body=body,
                    api_key=s.cloud_api_key,
                    key_lookup=lambda k: s.key_for_kiosk(k, svc.schedule.known_kiosks()),
                    skew_s=s.auth_skew_s, replay=None if path in REPLAY_EXEMPT else svc.replay)
            except AuthFailure as af:
                svc.metrics.count("AuthFailures", Route=route_label(path))
                log.info(json.dumps({"route": route_label(path), "method": method, "status": 401,
                                     "reason": af.message}))
                return await self._send_error(send, t0, 401, af.code, af.message)
            scope["hid.kiosk_id"] = kiosk_id

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status_box = {"status": 500}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_box["status"] = message["status"]
                latency = str(int((time.perf_counter() - t0) * 1000)).encode()
                message = {**message, "headers": [*message.get("headers", []), (b"x-latency-ms", latency),
                                                  (b"x-server-time", str(int(time.time())).encode())]}
            await send(message)

        try:
            await self.app(scope, replay_receive, send_wrapper)
        finally:
            ms = (time.perf_counter() - t0) * 1000
            label = route_label(path)
            svc.metrics.put("RequestLatencyMs", ms, Route=label)
            if status_box["status"] >= 500:
                svc.metrics.count("ServerErrors", Route=label)
            if label not in ("/v1/health", "/health"):
                log.info(json.dumps({"route": label, "method": method, "status": status_box["status"],
                                     "latency_ms": round(ms, 1), "kiosk_id": kiosk_id}))
