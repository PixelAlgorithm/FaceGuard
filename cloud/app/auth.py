"""Edge -> cloud request signing (docs/API.md §0). Stdlib only, so the edge can import or copy it.

Headers: X-Kiosk-Id, X-Timestamp (epoch seconds), X-Signature, X-Api-Key.
X-Signature = hex(HMAC-SHA256(key, "METHOD\\nPATH\\nX-Timestamp\\nhex(sha256(body))"))
- key  = the kiosk key string encoded as UTF-8 (the 64-char value in .env is used as-is, not hex-decoded)
- PATH = URL path plus "?query" when a query string is present (e.g. "/v1/revocations?since=7"). A signature
         over the bare path is refused for a request with a query (the query would be unauthenticated), unless
         the transition switch CLOUD_ACCEPT_BARE_PATH_SIG=1 is set.
- body = raw request bytes (b"" for GET), so multipart bodies are covered too.
Window: |server_now - X-Timestamp| <= 60 s. Non-GET requests (except the idempotent /v1/sync) are
additionally single-use within the window (replay guard keyed by kiosk + signature, kept in the shared KV store
with a TTL so every worker / instance sees it) — re-sign when retrying.
Clock skew: every response carries X-Server-Time (epoch s); a kiosk whose clock drifts should sign with
local_time + (server_time - local_time) learned from /v1/health.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time

HEADER_KIOSK = "x-kiosk-id"
HEADER_TS = "x-timestamp"
HEADER_SIG = "x-signature"
HEADER_API_KEY = "x-api-key"


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def string_to_sign(method: str, path: str, timestamp: str, body: bytes) -> str:
    return f"{method.upper()}\n{path}\n{timestamp}\n{body_sha256_hex(body)}"


def sign_request(key: str, method: str, path: str, timestamp: str, body: bytes) -> str:
    return hmac.new(key.encode("utf-8"), string_to_sign(method, path, timestamp, body).encode("utf-8"),
                    hashlib.sha256).hexdigest()


def signed_headers(*, kiosk_id: str, key: str, api_key: str, method: str, path: str, body: bytes = b"",
                   now: float | None = None) -> dict[str, str]:
    """Headers for one request. `path` must include the query string if the request has one."""
    ts = str(int(time.time() if now is None else now))
    return {
        "X-Kiosk-Id": kiosk_id,
        "X-Timestamp": ts,
        "X-Signature": sign_request(key, method, path, ts, body),
        "X-Api-Key": api_key,
    }


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class ReplayCache:
    """Per-process replay memory (unit tests / tools only; the app uses KvReplayGuard)."""

    def __init__(self, ttl_s: float) -> None:
        self._ttl = ttl_s
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, sig: str, now: float | None = None) -> bool:
        t = time.monotonic() if now is None else now
        with self._lock:
            if len(self._seen) > 10_000:
                self._seen = {k: v for k, v in self._seen.items() if v > t}
            exp = self._seen.get(sig)
            if exp is not None and exp > t:
                return False
            self._seen[sig] = t + self._ttl
            return True


class KvReplayGuard:
    """Replay guard shared by every worker: put_if_absent(ns "replay", kiosk:sig) with an absolute TTL of
    2x the skew window. A store failure propagates (the caller answers 503, never accepts unchecked)."""

    NS = "replay"

    def __init__(self, kv, ttl_s: float, now_fn=time.time) -> None:
        self._kv = kv
        self._ttl = ttl_s
        self._now = now_fn

    def check_and_add(self, sig: str, now: float | None = None) -> bool:
        t = self._now() if now is None else now
        return bool(self._kv.put_if_absent(self.NS, sig, {"seen_at": int(t)}, ttl=int(t + self._ttl) + 1))


class AuthFailure(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def verify_request(
    *,
    headers: dict[str, str],
    method: str,
    path: str,
    query_string: str,
    body: bytes,
    api_key: str,
    key_lookup,
    skew_s: int,
    replay: ReplayCache | KvReplayGuard | None,
    now: float | None = None,
    accept_bare_path: bool = False,
) -> str:
    """Returns the authenticated kiosk_id or raises AuthFailure. `headers` keys must be lower-case."""
    kiosk_id = headers.get(HEADER_KIOSK, "")
    ts = headers.get(HEADER_TS, "")
    sig = headers.get(HEADER_SIG, "").lower()
    presented_key = headers.get(HEADER_API_KEY, "")
    if not (kiosk_id and ts and sig and presented_key):
        raise AuthFailure("UNAUTHORIZED", "missing auth headers (X-Kiosk-Id, X-Timestamp, X-Signature, X-Api-Key)")
    if not constant_time_eq(presented_key, api_key):
        raise AuthFailure("UNAUTHORIZED", "invalid api key")
    try:
        ts_int = int(ts)
    except ValueError as exc:
        raise AuthFailure("UNAUTHORIZED", "X-Timestamp must be epoch seconds") from exc
    t_now = time.time() if now is None else now
    if abs(t_now - ts_int) > skew_s:
        raise AuthFailure("UNAUTHORIZED", f"timestamp outside +/-{skew_s}s window")
    key = key_lookup(kiosk_id)
    if not key:
        raise AuthFailure("UNAUTHORIZED", "unknown kiosk")
    candidates = [path + "?" + query_string] if query_string else [path]
    if query_string and accept_bare_path:
        candidates.append(path)
    if not any(constant_time_eq(sign_request(key, method, p, ts, body), sig) for p in candidates):
        raise AuthFailure("UNAUTHORIZED", "bad signature")
    if replay is not None and method.upper() != "GET" and not replay.check_and_add(f"{kiosk_id}:{sig}"):
        raise AuthFailure("UNAUTHORIZED", "replayed request (re-sign retries)")
    return kiosk_id
