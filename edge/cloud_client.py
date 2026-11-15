"""Edge -> cloud calls (only when CLOUD_API_URL is set). Every call is timeout-bounded.

Auth headers per docs/API.md 0: X-Kiosk-Id, X-Timestamp, X-Signature = hex HMAC-SHA256(kiosk_key,
METHOD\\nPATH\\nX-Timestamp\\nsha256(body)), X-Api-Key. Uses edge/offline/signing.py when present.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any

import httpx

from edge.config import Settings, Thresholds
from edge.policy.signals import CloudMatch

log = logging.getLogger("edge.cloud")


class CloudUnavailable(Exception):
    """The cloud could not be used: transport error / timeout (status None), 401 (our kiosk signature or key
    was rejected) or a 5xx. `connectivity_miss` = it says something about reachability (transport error or 5xx)
    and should count as a heartbeat miss; a 401 is a configuration problem, not an outage."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status

    @property
    def connectivity_miss(self) -> bool:
        return self.status is None or self.status >= 500


class CloudRejected(Exception):
    """The cloud answered and refused the request (a 4xx other than 401): not an outage, never a miss.
    `code` / `message` / `reason` come from the cloud error body when it has one (`reason` is forwarded verbatim
    by the edge, API.md 3.18.6); `retry_after_s` from Retry-After."""

    def __init__(self, status: int, code: str, message: str, retry_after_s: int | None = None,
                 reason: str | None = None) -> None:
        super().__init__(message)
        self.status, self.code, self.message, self.retry_after_s = status, code, message, retry_after_s
        self.reason = reason


def _cloud_error(resp: httpx.Response, what: str) -> Exception:
    """Map a non-2xx cloud response: 401 / 5xx -> CloudUnavailable; any other status -> CloudRejected."""
    if resp.status_code == 401 or resp.status_code >= 500:
        return CloudUnavailable(f"{what} HTTP {resp.status_code}", resp.status_code)
    body = _safe_json(resp)
    err = body.get("error") if isinstance(body, dict) else None
    code = str(err.get("code")) if isinstance(err, dict) and err.get("code") else f"HTTP_{resp.status_code}"
    msg = str(err.get("message")) if isinstance(err, dict) and err.get("message") else f"{what} HTTP {resp.status_code}"
    retry = None
    raw = resp.headers.get("Retry-After")
    if raw:
        try:
            retry = max(0, int(float(raw)))
        except ValueError:
            retry = None
    reason = err.get("reason") if isinstance(err, dict) else None
    reason = str(reason)[:64] if isinstance(reason, str) and reason else None
    return CloudRejected(resp.status_code, code, msg[:300], retry, reason)


CLOCK_DRIFT_CORRECT_S = 30.0  # sign with server time once |X-Server-Time - local| exceeds this
# Keep-alive for the match client. Attempts arrive 7-21 s apart; httpx's default 5 s expiry made every
# /v1/match open a new TCP+TLS connection (~0.67-0.73 s to us-east-1 vs ~0.22 s warm), past the 700 ms
# Rekognition budget -> attempt OFFLINE (P7). Kept below the cloud's uvicorn --timeout-keep-alive (75 s,
# cloud/infra/templates/user_data.sh.tmpl) so the server never closes a connection we are about to reuse.
KEEPALIVE_EXPIRY_S = 60.0
MATCH_POOL_LIMITS = httpx.Limits(max_connections=100, max_keepalive_connections=20,  # httpx defaults
                                 keepalive_expiry=KEEPALIVE_EXPIRY_S)
OTP_CLOUD_ERROR_STATUS = frozenset({401, 429})  # + every 5xx: the cloud did not judge the code (R11)
WARM_SKIP_S = 20.0  # session/start warm-up is skipped if the client completed a request this recently


def _local_sign(key: str, method: str, path: str, ts: str, body: bytes) -> str:
    msg = f"{method.upper()}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}".encode()
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def auth_headers(settings: Settings, method: str, path: str, body: bytes, now_s: int | None = None) -> dict[str, str]:
    """API.md 0 headers. HMAC key = the .env string encoded as UTF-8 (not hex-decoded)."""
    ts = int(time.time() if now_s is None else now_s)
    try:  # shared helper owned by policy-engine (same formula)
        from edge.offline.signing import sign_request
    except ImportError:
        return {"X-Kiosk-Id": settings.kiosk_id, "X-Timestamp": str(ts), "X-Api-Key": settings.cloud_api_key,
                "X-Signature": _local_sign(settings.kiosk_hmac_key, method, path, str(ts), body)}
    return sign_request(method, path, body, kiosk_id=settings.kiosk_id,
                        kiosk_key=settings.kiosk_hmac_key.encode("utf-8"),
                        api_key=settings.cloud_api_key or None, now_s=ts)


class CloudClient:
    def __init__(self, settings: Settings, thresholds: Thresholds,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.match_timeout_s = float(thresholds.get("latency_budget_ms.rekognition_timeout")) / 1000.0
        self.health_path = str(thresholds.get("connectivity.health_path"))
        self.warm_timeout_s = float(thresholds.get("connectivity.heartbeat_timeout_ms")) / 1000.0
        self._transport = transport
        self._client: httpx.AsyncClient | None = None
        self.clock_offset_s = 0.0  # server - local, applied only when drift > CLOCK_DRIFT_CORRECT_S
        self._last_used: float | None = None  # monotonic time this client last got a response
        self._warm_task: asyncio.Task[None] | None = None
        self.warmups_started = 0

    @property
    def enabled(self) -> bool:
        return self.settings.cloud_enabled

    async def start(self) -> None:
        if self.enabled and self._client is None:
            self._client = httpx.AsyncClient(base_url=self.settings.cloud_api_url, transport=self._transport,
                                             timeout=httpx.Timeout(5.0, connect=1.0), limits=MATCH_POOL_LIMITS)

    async def stop(self) -> None:
        task, self._warm_task = self._warm_task, None
        if task is not None and not task.done():
            task.cancel()
            await asyncio.wait({task}, timeout=1.0)
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def warm_up(self) -> bool:
        """Fire-and-forget GET connectivity.health_path through THIS client (the /v1/match client), so the
        attempt's match finds a warm keep-alive connection. Called at session/start and never awaited there.
        Skipped when the client got a response within WARM_SKIP_S or a warm-up is already in flight.
        Never raises; returns True if a warm-up was started."""
        if not self.enabled or self._client is None:
            return False
        if self._warm_task is not None and not self._warm_task.done():
            return False
        if self._last_used is not None and time.monotonic() - self._last_used < WARM_SKIP_S:
            return False
        try:
            self._warm_task = asyncio.get_running_loop().create_task(self._warm(), name="cloud-warm-up")
        except RuntimeError:  # no running event loop
            return False
        self.warmups_started += 1
        return True

    async def _warm(self) -> None:
        client, t = self._client, time.perf_counter()
        if client is None:
            return
        try:
            resp = await client.get(self.health_path, timeout=self.warm_timeout_s)
        except Exception as exc:  # noqa: BLE001 - a failed warm-up only means the next match may be cold
            log.info(json.dumps({"event": "cloud_warm_up", "ok": False, "error": type(exc).__name__,
                                 "latency_ms": round((time.perf_counter() - t) * 1000.0, 1)}))
            return
        self._last_used = time.monotonic()
        self._observe_server_time(resp)
        log.info(json.dumps({"event": "cloud_warm_up", "ok": True, "status": resp.status_code,
                             "latency_ms": round((time.perf_counter() - t) * 1000.0, 1)}))

    def _now_s(self) -> int:
        return int(time.time() + self.clock_offset_s)

    def _observe_server_time(self, resp: httpx.Response) -> bool:
        """Learn the cloud clock from X-Server-Time (epoch s). Returns True if the offset changed."""
        raw = resp.headers.get("X-Server-Time")
        if not raw:
            return False
        try:
            drift = float(raw) - time.time()
        except ValueError:
            return False
        new = drift if abs(drift) > CLOCK_DRIFT_CORRECT_S else 0.0
        changed = abs(new - self.clock_offset_s) > 1.0
        if changed:
            log.warning("kiosk/cloud clock drift %.0f s -> signing with server-corrected time", drift)
        self.clock_offset_s = new
        return changed

    async def _send(self, method: str, path: str, body: bytes, timeout_s: float,
                    content_type: str | None = "application/json",
                    extra_headers: dict[str, str] | None = None) -> httpx.Response:
        if not self.enabled or self._client is None:
            raise CloudUnavailable("cloud not configured")
        for attempt in (1, 2):
            headers = auth_headers(self.settings, method, path, body, now_s=self._now_s())
            if content_type:
                headers["Content-Type"] = content_type
            if extra_headers:
                headers.update(extra_headers)
            try:
                resp = await self._client.request(method, path, content=body or None, headers=headers,
                                                  timeout=timeout_s)
            except httpx.HTTPError as exc:
                raise CloudUnavailable(f"{type(exc).__name__}") from exc  # status None = transport error
            self._last_used = time.monotonic()  # a response => the pooled connection is warm
            changed = self._observe_server_time(resp)
            if resp.status_code == 401 and changed and attempt == 1:
                continue  # signature rejected because of clock skew: re-sign once with server time
            return resp
        return resp

    async def _post(self, path: str, json_body: dict[str, Any], timeout_s: float) -> httpx.Response:
        body = json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        return await self._send("POST", path, body, timeout_s)

    async def match(self, attempt_id: str, jpeg: bytes, claimed_user_id: str | None, *,
                    timeout_s: float | None = None) -> CloudMatch:
        """Rekognition match via the cloud; any failure -> CloudMatch(ok=False) (attempt => OFFLINE).

        `timeout_s` = per-phase httpx timeout (default latency_budget_ms.rekognition_timeout); the early
        probe passes its longer latency_budget_ms.rekognition_probe_deadline. Callers also bound the TOTAL
        time with asyncio.wait_for (httpx timeouts are per phase)."""
        payload = {
            "attempt_id": attempt_id,
            "kiosk_id": self.settings.kiosk_id,
            "image_b64": base64.b64encode(jpeg).decode(),
            "mode": "1:1" if claimed_user_id else "1:N",
            "claimed_user_id": claimed_user_id,
            "max_users": 2,
        }
        t = time.perf_counter()
        try:
            resp = await self._post("/v1/match", payload, timeout_s or self.match_timeout_s)
            log.info(json.dumps({"event": "cloud_match", "attempt_id": attempt_id, "status": resp.status_code,
                                 "latency_ms": round((time.perf_counter() - t) * 1000.0, 1)}))
            if resp.status_code != 200:
                return CloudMatch(ok=False)
            data = resp.json()
            return CloudMatch(
                ok=True,
                top1_user=data.get("user_id"),
                top1_similarity=data.get("similarity"),
                runner_up_similarity=data.get("runner_up_similarity"),
            )
        except (CloudUnavailable, ValueError) as exc:
            log.info("cloud match unavailable: %s", exc)
            return CloudMatch(ok=False)

    async def otp_send(self, attempt_id: str, user_id: str) -> dict[str, Any]:
        """CloudUnavailable = transport error / 401 / 5xx (only transport + 5xx are connectivity misses);
        CloudRejected = the cloud refused (404 no e-mail on file, 429 resend throttle, 422 ...)."""
        resp = await self._post("/v1/otp/send", {"attempt_id": attempt_id, "user_id": user_id,
                                                 "channel": "email"}, 5.0)
        if resp.status_code not in (200, 201):
            raise _cloud_error(resp, "otp/send")
        body = _safe_json(resp)
        if not isinstance(body, dict):
            raise CloudUnavailable("otp/send: unreadable response body", resp.status_code)
        return body

    async def otp_verify(self, attempt_id: str, otp_id: str, code: str) -> bool | None:
        """True/False = the cloud's verdict on the code; None = the cloud could not judge it (transport error
        or timeout, 401 = our kiosk signature/key was rejected, 429, any 5xx such as 503, or an unreadable
        200 body). None is a cloud error, not a wrong code: DECISION_POLICY R11 drops EMAIL_OTP without
        counting a FALLBACK_FAILED. Other 4xx (unknown / expired / used otp_id) -> False (counted)."""
        try:
            resp = await self._post("/v1/otp/verify", {"otp_id": otp_id, "attempt_id": attempt_id,
                                                       "code": code}, 3.0)
        except CloudUnavailable:
            return None
        if resp.status_code in OTP_CLOUD_ERROR_STATUS or resp.status_code >= 500:
            log.info(json.dumps({"event": "otp_verify_cloud_error", "attempt_id": attempt_id,
                                 "status": resp.status_code}))
            return None
        if resp.status_code != 200:
            return False
        body = _safe_json(resp)
        if not isinstance(body, dict) or not isinstance(body.get("verified"), bool):
            return None
        return body["verified"]

    async def enroll(self, meta: dict[str, Any], jpegs: list[bytes]) -> dict[str, Any]:
        payload = {**meta, "images_b64": [base64.b64encode(j).decode() for j in jpegs]}
        resp = await self._post("/v1/enroll", payload, 15.0)
        return {"status": resp.status_code, "body": _safe_json(resp)}

    async def delete_user(self, user_id: str) -> dict[str, Any]:
        resp = await self._send("DELETE", f"/v1/enroll/{user_id}", b"", 10.0, content_type=None)
        return {"status": resp.status_code, "body": _safe_json(resp)}

    async def admin(self, method: str, path: str, json_body: dict[str, Any] | None = None,
                    timeout_s: float = 8.0) -> Any:
        """Cloud admin route (API.md 4.9): kiosk HMAC + X-Admin-Token (CLOUD_ADMIN_TOKEN, else ADMIN_TOKEN).
        Returns the parsed 2xx body. Raises CloudUnavailable (transport / 401 / 5xx / unreadable body) or
        CloudRejected (any other 4xx, with the cloud's error code + message). Bodies are never logged: the
        code-rotation response carries one-time plaintext codes."""
        token = self.settings.cloud_admin_token
        if not token:
            raise CloudUnavailable("no admin token configured for the cloud (CLOUD_ADMIN_TOKEN / ADMIN_TOKEN)")
        body = b"" if json_body is None else json.dumps(json_body, separators=(",", ":")).encode("utf-8")
        t = time.perf_counter()
        resp = await self._send(method, path, body, timeout_s, content_type="application/json" if body else None,
                                extra_headers={"X-Admin-Token": token})
        log.info(json.dumps({"event": "cloud_admin", "method": method, "path": path.split("?")[0],
                             "status": resp.status_code,
                             "latency_ms": round((time.perf_counter() - t) * 1000.0, 1)}))
        if not 200 <= resp.status_code < 300:
            raise _cloud_error(resp, f"{method} {path.split('?')[0]}")
        if resp.status_code == 204 or not resp.content:
            return {}
        data = _safe_json(resp)
        if data is None:
            raise CloudUnavailable(f"{method} {path.split('?')[0]}: unreadable response body", resp.status_code)
        return data


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None
