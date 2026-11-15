"""Cloud request signing (docs/API.md §0) -- reusable by edge-ml and the cloud verifier.

Headers: X-Kiosk-Id, X-Timestamp (epoch s), X-Api-Key, and
X-Signature = hex HMAC-SHA256(kiosk_key, f"{METHOD}\\n{PATH}\\n{X-Timestamp}\\n{sha256_hex(body)}").
PATH is the URL path plus "?query" when a query string is present (the exact bytes on the wire,
httpx `url.raw_path`); the cloud stops accepting a bare-path signature for a request with a query (F5).
Server accepts |now - X-Timestamp| <= 60 s.

Clock skew (EO-04): every cloud response carries X-Server-Time (epoch s). KioskAuth learns the offset from
every signed response and, once |server - local| exceeds CLOCK_DRIFT_CORRECT_S, signs with the corrected
time (same rule as edge/cloud_client.py). A 401 that arrives while the offset changed is re-signed once.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import time
from collections.abc import Generator, Mapping

import httpx

MAX_SKEW_S = 60
CLOCK_DRIFT_CORRECT_S = 30.0  # sign with server time once |X-Server-Time - local| exceeds this (cloud_client.py)
OFFSET_CHANGE_S = 1.0  # an offset move smaller than this is jitter, not a new skew


def string_to_sign(method: str, path: str, timestamp: int | str, body: bytes) -> bytes:
    return f"{method.upper()}\n{path}\n{timestamp}\n{hashlib.sha256(body).hexdigest()}".encode()


def sign_request(method: str, path: str, body: bytes, *, kiosk_id: str, kiosk_key: bytes, api_key: str | None = None,
                 now_s: int | None = None) -> dict[str, str]:
    ts = int(time.time() if now_s is None else now_s)
    sig = hmac.new(kiosk_key, string_to_sign(method, path, ts, body), hashlib.sha256).hexdigest()
    headers = {"X-Kiosk-Id": kiosk_id, "X-Timestamp": str(ts), "X-Signature": sig}
    if api_key:
        headers["X-Api-Key"] = api_key
    return headers


def verify_request(method: str, path: str, body: bytes, headers: Mapping[str, str], *, kiosk_key: bytes,
                   now_s: int | None = None, max_skew_s: int = MAX_SKEW_S) -> bool:
    lower = {k.lower(): v for k, v in headers.items()}
    try:
        ts = int(lower["x-timestamp"])
        sig = lower["x-signature"]
    except (KeyError, ValueError):
        return False
    now = int(time.time() if now_s is None else now_s)
    if abs(now - ts) > max_skew_s:
        return False
    expected = hmac.new(kiosk_key, string_to_sign(method, path, ts, body), hashlib.sha256).hexdigest()
    if not isinstance(sig, str):
        return False
    return hmac.compare_digest(expected.encode(), sig.encode("utf-8", "surrogatepass"))  # bytes: never raises


class KioskAuth(httpx.Auth):
    """httpx auth hook: signs every request (the body must be fully built, i.e. not streamed) with the
    server-corrected clock, learns X-Server-Time from each response and re-signs once on a skew 401."""

    requires_request_body = True

    def __init__(self, kiosk_id: str, kiosk_key: bytes, api_key: str | None = None) -> None:
        self.kiosk_id, self.kiosk_key, self.api_key = kiosk_id, kiosk_key, api_key
        self.clock_offset_s = 0.0  # server - local; 0 until the drift exceeds CLOCK_DRIFT_CORRECT_S
        self.last_drift_s: float | None = None  # last measured server - local (for /v1/mode, alerts)

    def now_s(self) -> int:
        return int(time.time() + self.clock_offset_s)

    def observe(self, response: httpx.Response) -> bool:
        """Learn the cloud clock from X-Server-Time. Returns True when the signing offset changed."""
        raw = response.headers.get("X-Server-Time")
        if not raw:
            return False
        try:
            drift = float(raw) - time.time()
        except ValueError:
            return False
        if not math.isfinite(drift):  # NaN / inf header: ignore
            return False
        self.last_drift_s = drift
        new = drift if abs(drift) > CLOCK_DRIFT_CORRECT_S else 0.0
        changed = abs(new - self.clock_offset_s) > OFFSET_CHANGE_S
        self.clock_offset_s = new
        return changed

    def _sign(self, request: httpx.Request) -> httpx.Request:
        path = request.url.raw_path.decode("ascii")  # path + "?query" exactly as sent (API.md §0)
        request.headers.update(sign_request(request.method, path, request.content or b"", kiosk_id=self.kiosk_id,
                                            kiosk_key=self.kiosk_key, api_key=self.api_key, now_s=self.now_s()))
        return request

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        response = yield self._sign(request)
        if self.observe(response) and response.status_code == 401:
            yield self._sign(request)  # rejected for clock skew: re-sign once with the server-corrected time
