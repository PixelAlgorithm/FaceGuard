"""Signed schedule bundle: canonical JSON, HMAC-SHA256 sign/verify, and the last-valid-bundle store.

Canonical form (docs/SURPRISE_CHALLENGES.md SC2.2): json.dumps(bundle_without_signature, sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode("utf-8"); signature = hex HMAC-SHA256 with
SCHEDULE_BUNDLE_HMAC_KEY. (Ed25519 is the production roadmap: kiosk would hold only the public key.)

Round-2 R6 (last valid bundle, LVB): a bundle that fails verification is rejected (alert) and never
replaces the LVB; data from an unverified bundle is never used.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edge.policy.engine import ScheduleCtx

ALG = "HMAC-SHA256"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle_signature(bundle: Mapping[str, Any], key: bytes) -> str:
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()


def sign_bundle(bundle: Mapping[str, Any], key: bytes, key_id: str = "demo-k1") -> dict[str, Any]:
    out = copy.deepcopy(dict(bundle))
    out.pop("signature", None)
    out["signature"] = {"alg": ALG, "key_id": key_id, "value": bundle_signature(out, key)}
    return out


def ct_equal(a: Any, b: Any) -> bool:
    """Constant-time equality of two strings that never raises: hmac.compare_digest() raises TypeError on
    non-ASCII str, so both sides are compared as UTF-8 bytes (lone surrogates included)."""
    if not (isinstance(a, str) and isinstance(b, str)):
        return False
    return hmac.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def verify_bundle(bundle: Any, key: bytes | None) -> bool:
    """True only for a correctly signed bundle; never raises (any malformed input -> False)."""
    if not key or not isinstance(bundle, Mapping):
        return False
    sig = bundle.get("signature")
    if not isinstance(sig, Mapping) or sig.get("alg") != ALG or not isinstance(sig.get("value"), str):
        return False
    try:
        expected = bundle_signature(bundle, key)
    except (TypeError, ValueError):  # content that cannot be canonicalised is not a valid bundle
        return False
    return ct_equal(sig["value"], expected)


def _version(b: Mapping[str, Any] | None) -> int:
    v = (b or {}).get("bundle_version")
    return v if isinstance(v, int) and not isinstance(v, bool) else -1


class BundleStore:
    """Holds the last valid bundle (LVB) for this kiosk; persists it atomically to `path`."""

    def __init__(self, path: Path, key: bytes | None, kiosk_id: str,
                 on_alert: Callable[[str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(UTC))  # injected wall clock (tests: fixed time of day)
        self._key = key
        self.kiosk_id = kiosk_id
        self._on_alert = on_alert
        self._lock = threading.RLock()
        self._lvb: dict[str, Any] | None = None
        self.confirmed_at: datetime | None = None  # wall time of the last cloud refresh (install / 304)
        self._refreshed_mono: float | None = None  # monotonic time of the same event (refresh age, R5)
        self.alerts: list[dict[str, Any]] = []
        self._file_sig: tuple[int, int] | None = None
        self._last_check = 0.0
        self._loaded_once = False  # the boot load is not a refresh; later verified file changes are
        self._load()

    # ------------------------------------------------------------ state
    @property
    def lvb(self) -> dict[str, Any] | None:
        self._maybe_reload()
        return self._lvb

    @property
    def version(self) -> int | None:
        lvb = self.lvb
        return _version(lvb) if lvb else None

    def refresh_age_s(self) -> float | None:
        """Real elapsed seconds since the cloud last refreshed/confirmed the bundle (None = never)."""
        return None if self._refreshed_mono is None else time.monotonic() - self._refreshed_mono

    def schedule_ctx(self, extra_revocations: tuple[Mapping[str, Any], ...] = ()) -> ScheduleCtx:
        with self._lock:
            lvb = self.lvb
            return ScheduleCtx(kiosk_id=self.kiosk_id, bundle=lvb, signature_valid=lvb is not None,
                               extra_revocations=tuple(extra_revocations), confirmed_at=self.confirmed_at,
                               refresh_age_s=self.refresh_age_s())

    def _maybe_reload(self, force: bool = False) -> None:
        """Pick up a re-signed bundle file (e.g. scripts/sign_bundle.py) without a restart.

        Checked at most once per second; an unverifiable file is rejected and the LVB kept (R6).
        A file reload is not a cloud refresh: it does not change the refresh age."""
        mono = time.monotonic()
        if not force and mono - self._last_check < 1.0:
            return
        with self._lock:
            self._last_check = mono
            try:
                st = self.path.stat()
            except OSError:
                return  # file removed: keep the in-memory LVB
            sig = (st.st_mtime_ns, st.st_size)
            if sig == self._file_sig:
                return
            self._file_sig = sig
            try:
                candidate = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._alert("BUNDLE_REJECTED", reason="unreadable bundle file", path=str(self.path))
                return
            ok, reason = self._acceptable(candidate)
            if not ok:
                self._alert("BUNDLE_REJECTED", reason=reason, path=str(self.path))
                return
            if self._lvb is not None and _version(candidate) < _version(self._lvb):
                self._alert("BUNDLE_REJECTED", reason="file older than the installed bundle",
                            version=_version(candidate), installed=_version(self._lvb))
                return
            # operator re-sign (scripts/sign_bundle.py): a verified bundle installed = a refresh (§5.1)
            self._lvb = candidate
            if self._loaded_once:
                self.confirmed_at, self._refreshed_mono = self._clock(), time.monotonic()

    # ------------------------------------------------------------ mutation
    def _alert(self, kind: str, **detail: Any) -> None:
        a = {"type": kind, "at": self._clock().isoformat(), **detail}
        self.alerts.append(a)
        del self.alerts[:-50]
        if self._on_alert:
            self._on_alert(kind, a)

    def _load(self) -> None:
        self._maybe_reload(force=True)
        self._loaded_once = True

    def _acceptable(self, candidate: Any) -> tuple[bool, str]:
        if not verify_bundle(candidate, self._key):
            return False, "signature verification failed"
        kiosks = candidate.get("kiosks") or {}
        scope = (candidate.get("scope") or {}).get("kiosk_ids")
        if self.kiosk_id not in kiosks or (scope is not None and self.kiosk_id not in scope):
            return False, f"bundle does not cover kiosk {self.kiosk_id}"
        return True, ""

    def install(self, candidate: Any, now: datetime) -> tuple[bool, str]:
        """Verify + install a received bundle. Never replaces the LVB with an unverified/older one."""
        with self._lock:
            ok, reason = self._acceptable(candidate)
            if not ok:
                self._alert("BUNDLE_REJECTED", reason=reason, version=_version(candidate))
                return False, reason
            if self._lvb is not None and _version(candidate) < _version(self._lvb):
                self._alert("BUNDLE_REJECTED", reason="older than the installed bundle",
                            version=_version(candidate), installed=_version(self._lvb))
                return False, "older version"
            if (self._lvb is not None and _version(candidate) == _version(self._lvb)
                    and str(candidate.get("issued_at", "")) < str(self._lvb.get("issued_at", ""))):
                self._alert("BUNDLE_REJECTED", reason="same version with an older issued_at",
                            version=_version(candidate))
                return False, "older issued_at for the same version"  # API.md 4.2 acceptance
            self._write(candidate)
            self._lvb = copy.deepcopy(candidate)
            self.confirmed_at, self._refreshed_mono = now, time.monotonic()
            return True, ""

    def mark_confirmed(self, now: datetime) -> None:
        """The cloud confirmed the installed bundle is still current (e.g. HTTP 304)."""
        with self._lock:
            if self._lvb is not None:
                self.confirmed_at, self._refreshed_mono = now, time.monotonic()

    def _write(self, bundle: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".bundle-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(bundle, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.path)
            st = self.path.stat()
            self._file_sig = (st.st_mtime_ns, st.st_size)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
