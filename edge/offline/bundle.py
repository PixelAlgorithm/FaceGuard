"""Signed schedule bundle: canonical JSON, HMAC-SHA256 sign/verify, and the last-valid-bundle store.

Canonical form (docs/SURPRISE_CHALLENGES.md SC2.2): json.dumps(bundle_without_signature, sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode("utf-8"); signature = hex HMAC-SHA256 with
SCHEDULE_BUNDLE_HMAC_KEY. (Ed25519 is the production roadmap: kiosk would hold only the public key.)

Round-2 R6 (last valid bundle, LVB): a bundle that fails verification is rejected (alert) and never
replaces the LVB; data from an unverified bundle is never used.

Key id (EO-02): the signature's `key_id` must equal the configured id (SCHEDULE_BUNDLE_KEY_ID, default
"demo-k1", the same default as the cloud), so a rotated-out key id is refused. LIMIT (documented, not fixed
here): HMAC-SHA256 is symmetric. Every kiosk holds the bundle-signing key itself, so one stolen kiosk can sign
a bundle for any kiosk; key_id pinning only makes rotation possible. Production needs an asymmetric signature
(Ed25519 / KMS ECDSA, kiosk holds public keys pinned by key_id) and signed feed / sync responses.

Anti-rollback (EO-09): one ordering rule for the cloud install and the on-disk file reload. A candidate is
newer when its bundle_version is higher, or the version is equal and issued_at is strictly later. An equal
(version, issued_at) is accepted only with identical content (a no-op). Anything older is rejected. A file
reload counts as a refresh only when the content actually changed (a `touch` is not a refresh).

Documented codes (EO-10): `decision_bundle` is the LVB without override codes whose value is publicly
documented (OVR-001..003, the fixture values in docs and config/schedule.example.json), unless the store was
built with allow_documented_codes=True (the runtime passes DEMO_MODE=1). `lvb` stays the verbatim signed
document (it still verifies). Every other signed field (e.g. `consumed_code_ids`) is used unchanged.

Durability (EO-M2): the LVB is written 0600 with fsync + atomic replace, and a copy is kept as
`<file>.bak`. When the main file is unreadable at boot, the verified .bak is loaded instead.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from edge.offline.crypto import write_private_atomic
from edge.policy.engine import ScheduleCtx

ALG = "HMAC-SHA256"
DEFAULT_KEY_ID = "demo-k1"  # cloud/app/config.py SCHEDULE_BUNDLE_KEY_ID default
BACKUP_SUFFIX = ".bak"
# Publicly documented demo override codes (SURPRISE_CHALLENGES SC2.4, config/schedule.example.json, test
# fixtures). Same list as cloud/app/services/code_hygiene.py; scripts/sign_bundle.py imports it from here.
DOC_OVERRIDE_CODES = {"OVR-001": "48213907", "OVR-002": "75530182", "OVR-003": "19064425"}
DOCUMENTED_CODE_IDS = frozenset(DOC_OVERRIDE_CODES)
EDGE_MIN_PBKDF2_ITERATIONS = 100000  # the edge verifies with max(declared, this) (edge/policy/fallback.py)
_DOC_MEMO: dict[tuple[int, str, str], bool] = {}  # (iterations, salt, hash) -> documented? (PBKDF2 is slow)


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


def verify_bundle(bundle: Any, key: bytes | None, key_id: str | None = None) -> bool:
    """True only for a correctly signed bundle; never raises (any malformed input -> False). With `key_id`,
    the signature must also name exactly that key id (EO-02: key rotation / pinning)."""
    if not key or not isinstance(bundle, Mapping):
        return False
    sig = bundle.get("signature")
    if not isinstance(sig, Mapping) or sig.get("alg") != ALG or not isinstance(sig.get("value"), str):
        return False
    if key_id is not None and not ct_equal(sig.get("key_id"), key_id):
        return False
    try:
        expected = bundle_signature(bundle, key)
    except (TypeError, ValueError):  # content that cannot be canonicalised is not a valid bundle
        return False
    return ct_equal(sig["value"], expected)


def _version(b: Mapping[str, Any] | None) -> int:
    v = (b or {}).get("bundle_version")
    return v if isinstance(v, int) and not isinstance(v, bool) else -1


def _issued(b: Mapping[str, Any] | None) -> datetime | None:
    raw = (b or {}).get("issued_at")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw)  # py3.11 parses a trailing "Z"
    except ValueError:
        return None
    return dt.astimezone(UTC) if dt.tzinfo is not None else None


def content_digest(bundle: Mapping[str, Any]) -> str:
    """sha256 over the canonical JSON of the whole signed bundle (signature included)."""
    return hashlib.sha256(canonical_json(bundle)).hexdigest()


def is_documented_code(code: Any, iterations: int) -> bool:
    """True if an override-code entry re-uses a documented code_id or its PBKDF2 hash matches a documented
    value at the declared or the edge's effective iteration count. A malformed entry counts as documented
    (it is unusable anyway, so it is dropped)."""
    if not isinstance(code, Mapping):
        return True
    if str(code.get("code_id", "")) in DOCUMENTED_CODE_IDS:
        return True
    salt_hex, want = str(code.get("salt", "")), str(code.get("hash", ""))
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return True
    hit = False
    for n in dict.fromkeys((iterations, max(iterations, EDGE_MIN_PBKDF2_ITERATIONS))):
        memo_key = (n, salt_hex, want)
        if memo_key not in _DOC_MEMO:
            _DOC_MEMO[memo_key] = any(ct_equal(hashlib.pbkdf2_hmac("sha256", v.encode(), salt, n).hex(), want)
                                      for v in DOC_OVERRIDE_CODES.values())
        hit = hit or _DOC_MEMO[memo_key]
    return hit


def without_documented_codes(bundle: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """(copy of `bundle` without documented override codes, dropped code_ids). The input is not modified."""
    out = copy.deepcopy(dict(bundle))
    oc = out.get("override_codes")
    if not isinstance(oc, dict) or not isinstance(oc.get("codes"), list):
        return out, []
    raw_it = oc.get("iterations")
    iterations = raw_it if isinstance(raw_it, int) and not isinstance(raw_it, bool) and raw_it > 0 else 1
    keep, dropped = [], []
    for c in oc["codes"]:
        if is_documented_code(c, iterations):
            dropped.append(str(c.get("code_id")) if isinstance(c, Mapping) else "?")
        else:
            keep.append(c)
    oc["codes"] = keep
    return out, dropped


class BundleStore:
    """Holds the last valid bundle (LVB) for this kiosk; persists it atomically to `path`."""

    def __init__(self, path: Path, key: bytes | None, kiosk_id: str,
                 on_alert: Callable[[str, dict[str, Any]], None] | None = None,
                 clock: Callable[[], datetime] | None = None, *, key_id: str | None = DEFAULT_KEY_ID,
                 allow_documented_codes: bool = False) -> None:
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(UTC))  # injected wall clock (tests: fixed time of day)
        self._key = key
        self.key_id = key_id  # None = any key id (tests / tools only)
        self.allow_documented_codes = bool(allow_documented_codes)  # DEMO_MODE=1 only (EO-10)
        self._view: tuple[int, dict[str, Any]] | None = None  # (id(_lvb), LVB minus documented codes)
        self.dropped_codes: list[str] = []  # documented code_ids removed from decision_bundle
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
    def decision_bundle(self) -> dict[str, Any] | None:
        """The LVB as the policy must use it (EO-10): publicly documented override codes removed unless
        allow_documented_codes (DEMO_MODE=1). Every other field, `consumed_code_ids` included, is unchanged.
        `lvb` stays the verbatim signed document (verifiable, for export / re-upload)."""
        lvb = self.lvb
        if lvb is None or self.allow_documented_codes:
            return lvb
        with self._lock:
            if self._view is None or self._view[0] != id(lvb):
                # fallback only: the LVB was set out of band (tests). install / boot / reload precompute it (OS-8)
                self._store_view(lvb, without_documented_codes(lvb))
            return self._view[1]

    def _store_view(self, lvb: dict[str, Any], prepared: tuple[dict[str, Any], list[str]]) -> None:
        view, dropped = prepared
        if dropped and dropped != self.dropped_codes:
            self._alert("BUNDLE_DOCUMENTED_CODES_DROPPED", version=_version(lvb), code_ids=dropped)
        self.dropped_codes = dropped
        self._view = (id(lvb), view)

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

        Checked at most once per second; an unverifiable or older file is rejected and the LVB kept (R6,
        EO-09: the same ordering rule as install()). Only a verified, strictly newer file after the boot load
        counts as a refresh (operator re-sign, §5.1); an unchanged file (touch) does not."""
        mono = time.monotonic()
        if not force and mono - self._last_check < 1.0:
            return
        with self._lock:
            self._last_check = mono
            try:
                st = self.path.stat()
            except OSError:
                if not self._loaded_once:
                    self._load_backup("bundle file missing")
                return  # file removed: keep the in-memory LVB
            sig = (st.st_mtime_ns, st.st_size)
            if sig == self._file_sig:
                return
            self._file_sig = sig
            try:
                candidate = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._alert("BUNDLE_REJECTED", reason="unreadable bundle file", path=str(self.path))
                if not self._loaded_once:
                    self._load_backup("unreadable bundle file")
                return
            cur = self._lvb
            if cur is not None and isinstance(candidate, Mapping) and content_digest(candidate) == content_digest(cur):
                return  # same signed content (touch / rewrite): not a refresh
            ok, reason = self._acceptable(candidate)
            if ok:
                ok, reason = self._newer_than_lvb(candidate)
            if not ok:
                self._alert("BUNDLE_REJECTED", reason=f"bundle file: {reason}", path=str(self.path),
                            version=_version(candidate) if isinstance(candidate, Mapping) else None)
                return
            self._set_lvb(candidate)
            if self._loaded_once:
                self.confirmed_at, self._refreshed_mono = self._clock(), time.monotonic()

    def _load_backup(self, why: str) -> None:
        """Boot only: the main file is missing / unreadable -> the verified `.bak` copy (EO-M2)."""
        bak = self.path.with_name(self.path.name + BACKUP_SUFFIX)
        try:
            candidate = json.loads(bak.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        ok, reason = self._acceptable(candidate)
        if not ok:
            self._alert("BUNDLE_REJECTED", reason=f"backup bundle: {reason}", path=str(bak))
            return
        self._set_lvb(candidate)
        self._alert("BUNDLE_BACKUP_LOADED", reason=why, path=str(bak), version=_version(candidate))

    # ------------------------------------------------------------ mutation
    def _alert(self, kind: str, **detail: Any) -> None:
        a = {"type": kind, "at": self._clock().isoformat(), **detail}
        self.alerts.append(a)
        del self.alerts[:-50]
        if self._on_alert:
            self._on_alert(kind, a)

    def _load(self) -> None:
        self._maybe_reload(force=True)
        self._prefer_newer_backup()
        self._loaded_once = True

    def _prefer_newer_backup(self) -> None:
        """Boot only (OS-5): a verified `.bak` newer than a readable main file wins (power loss between the .bak
        write and the main replace, or an older bundle copied over the main file while the edge was stopped)."""
        if self._lvb is None:
            return  # main missing / unreadable / rejected: _load_backup already handled it
        bak = self.path.with_name(self.path.name + BACKUP_SUFFIX)
        try:
            candidate = json.loads(bak.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not self._acceptable(candidate)[0] or content_digest(candidate) == content_digest(self._lvb):
            return
        main_version = _version(self._lvb)
        newer, _reason = self._newer_than_lvb(candidate)
        if not newer:
            return
        self._set_lvb(candidate)
        self._alert("BUNDLE_ROLLBACK_SUSPECTED", reason="backup bundle newer than the main file at boot",
                    path=str(bak), main_version=main_version, backup_version=_version(candidate))

    def _acceptable(self, candidate: Any) -> tuple[bool, str]:
        if not verify_bundle(candidate, self._key, self.key_id):
            return False, "signature verification failed"
        kiosks = candidate.get("kiosks") or {}
        scope = (candidate.get("scope") or {}).get("kiosk_ids")
        if self.kiosk_id not in kiosks or (scope is not None and self.kiosk_id not in scope):
            return False, f"bundle does not cover kiosk {self.kiosk_id}"
        return True, ""

    def _newer_than_lvb(self, candidate: Mapping[str, Any]) -> tuple[bool, str]:
        """EO-09 ordering rule shared by install() and the file reload (API.md 4.2 acceptance)."""
        if self._lvb is None:
            return True, ""
        cur = self._lvb
        if _version(candidate) < _version(cur):
            return False, "older version"
        if _version(candidate) > _version(cur):
            return True, ""
        new_t, cur_t = _issued(candidate), _issued(cur)
        if new_t is None or (cur_t is not None and new_t < cur_t):
            return False, "older issued_at for the same version"
        if cur_t is not None and new_t == cur_t and content_digest(candidate) != content_digest(cur):
            return False, "different content for the same version and issued_at"
        return True, ""

    def _prepare(self, candidate: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]] | None:
        """The documented-code view of a candidate (PBKDF2, memoised); None when documented codes are allowed.
        Computed when the LVB is set, never on the decision read (OS-8)."""
        return None if self.allow_documented_codes else without_documented_codes(candidate)

    def _set_lvb(self, candidate: Mapping[str, Any],
                 prepared: tuple[dict[str, Any], list[str]] | None = None) -> None:
        lvb = copy.deepcopy(dict(candidate))
        if prepared is None and not self.allow_documented_codes:
            prepared = self._prepare(lvb)
        self._lvb, self._view = lvb, None
        if prepared is not None:
            self._store_view(lvb, prepared)

    def install(self, candidate: Any, now: datetime) -> tuple[bool, str]:
        """Verify + install a received bundle. Never replaces the LVB with an unverified/older one."""
        # OS-8: the PBKDF2 documented-code scan runs here, before the lock, so decisions never wait for it
        prepared = self._prepare(candidate) if verify_bundle(candidate, self._key, self.key_id) else None
        with self._lock:
            ok, reason = self._acceptable(candidate)
            if not ok:
                self._alert("BUNDLE_REJECTED", reason=reason, version=_version(candidate)
                            if isinstance(candidate, Mapping) else None)
                return False, reason
            ok, reason = self._newer_than_lvb(candidate)
            if not ok:
                self._alert("BUNDLE_REJECTED", reason=reason, version=_version(candidate),
                            installed=_version(self._lvb))
                return False, reason
            self._write(candidate)
            self._set_lvb(candidate, prepared)
            self.confirmed_at, self._refreshed_mono = now, time.monotonic()
            return True, ""

    def mark_confirmed(self, now: datetime) -> None:
        """The cloud confirmed the installed bundle is still current (e.g. HTTP 304)."""
        with self._lock:
            if self._lvb is not None:
                self.confirmed_at, self._refreshed_mono = now, time.monotonic()

    def _write(self, bundle: Mapping[str, Any]) -> None:
        """0600, fsync, atomic replace (EO-M2); the .bak copy is written first so one of the two is always a
        complete verified bundle."""
        data = json.dumps(bundle, ensure_ascii=False, indent=1).encode("utf-8")
        write_private_atomic(self.path.with_name(self.path.name + BACKUP_SUFFIX), data, prefix=".bundle-bak-")
        write_private_atomic(self.path, data, prefix=".bundle-")
        st = self.path.stat()
        self._file_sig = (st.st_mtime_ns, st.st_size)
