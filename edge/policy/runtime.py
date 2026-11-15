"""PolicyRuntime -- the facade edge-ml calls (docs/DECISION_POLICY.md .2, docs/API.md v1.1).

    rt = PolicyRuntime.from_env(project_root); rt.start()
    body = rt.decide(attempt_signals, latency_ms={"total": t, "liveness": a, "match": b})
    body = rt.resolve_challenge(attempt_id, ChallengeEvidence(...))
    body = rt.resolve_fallback(attempt_id, FallbackSubmission(...))

decide()/resolve_*() return the API.md v1.1 DecisionResponse dict (DECISION_POLICY §10 + "stage"); the
minimal SC2.5 record is written (encrypted) BEFORE they return (P9). If it cannot be written the answer
is DENY + SYSTEM_ERROR. Raises AttemptClosedError (-> 409 ATTEMPT_CLOSED) for an attempt that already
reached ALLOW/DENY, AttemptNotFoundError (-> 404) for an unknown step-up attempt, CloudUnavailableError
(-> 503) from sync_now() when the cloud cannot be reached.
Clocks (§2): the wall clock (= demo clock with DEMO_MODE=1) drives t0, schedule, bundle freshness and
record stamps; the real clock drives step-up / nonce TTLs, TOTP and the rate limiter (monotonic).
"""

from __future__ import annotations

import logging
import math
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import httpx
from pydantic import ValidationError

from edge.offline.bundle import BundleStore
from edge.offline.connectivity import OFFLINE, ONLINE, SYNCING, ConnectivityMonitor
from edge.offline.credentials import CredentialStore
from edge.offline.erasures import PendingErasures
from edge.offline.migrate import migrate_legacy_log
from edge.offline.signing import KioskAuth
from edge.offline.store import RECORD_FIELDS, DecisionLog, SqliteFallbackState, minimal_record
from edge.offline.sync import RevocationOverlay, SyncAgent
from edge.policy import schedule as sched_mod
from edge.policy.challenge import new_challenge
from edge.policy.engine import (
    DENY,
    STEP_UP,
    Decision,
    evaluate,
    online_bundle_ok,
    system_error,
    user_meta,
)
from edge.policy.fallback import FallbackVerifier, InMemoryFallbackState
from edge.policy.liveness import enforced
from edge.policy.ratelimit import RateLimiter
from edge.policy.signals import AttemptSignals, ChallengeEvidence, FallbackSubmission
from edge.policy.stepup import OPEN, SessionClosed, StepUpSession, expire_if_due, open_session
from edge.policy.stepup import drop_method as _drop_method
from edge.policy.stepup import resolve_challenge as _resolve_challenge
from edge.policy.stepup import resolve_fallback as _resolve_fallback
from edge.policy.thresholds import Thresholds

IST = ZoneInfo("Asia/Kolkata")
log = logging.getLogger("edge.policy.runtime")  # never logs secrets, codes or biometric data
ENV_KEYS = ("KIOSK_ID", "EDGE_DATA_KEY", "SCHEDULE_BUNDLE_HMAC_KEY", "CARD_ID_PEPPER", "KIOSK_HMAC_KEY",
            "CLOUD_API_URL", "CLOUD_API_KEY", "FORCE_OFFLINE", "DEMO_MODE", "EDGE_DATA_DIR", "BUNDLE_PATH")
MAX_DEMO_OFFSET_S = 7 * 86400  # demo clock: +-7 days (larger offsets overflow datetime / brick the runtime)
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
NEVER_STORED = ["images", "face_crops", "depth_maps", "embeddings", "display_names", "totp_values", "raw_card_ids"]


class AttemptClosedError(Exception):
    """Attempt already reached a terminal ALLOW/DENY (HTTP 409 ATTEMPT_CLOSED)."""


class AttemptNotFoundError(Exception):
    """No step-up session for this attempt (HTTP 404 ATTEMPT_NOT_FOUND)."""


class CloudUnavailableError(Exception):
    """Cloud not configured / forced offline / unreachable (HTTP 503 CLOUD_UNAVAILABLE)."""

    def __init__(self, message: str, report: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.report = dict(report or {})


def read_env(project_root: Path) -> dict[str, str]:
    """`.env` at the project root, overridden by the process environment. Values are never logged."""
    env: dict[str, str] = {}
    p = Path(project_root) / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.split(" #", 1)[0].strip().strip('"').strip("'")
    env.update({k: os.environ[k] for k in ENV_KEYS if k in os.environ})
    return env


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z") if dt else None


class _FixedRng:
    """Forced random-challenge draw (FORCE / FORCE_NEXT): `forced` makes the engine bypass the rate (even 0.0)."""

    forced = True

    def __init__(self, value: float, on_use: Callable[[], None] | None = None) -> None:
        self.value, self.on_use = value, on_use

    def random(self) -> float:
        if self.on_use:
            self.on_use()
        return self.value


class PolicyRuntime:
    def __init__(self, *, cfg: Thresholds, kiosk_id: str, bundles: BundleStore, log: DecisionLog,
                 monitor: ConnectivityMonitor, credentials: CredentialStore, overlay: RevocationOverlay,
                 card_pepper: bytes | None, client: httpx.Client | None = None, kiosk_key: bytes | None = None,
                 demo_mode: bool = False, rng: Any = None, fallback_state: Any = None,
                 clock: Callable[[], datetime] | None = None, mono: Callable[[], float] | None = None,
                 erasures: PendingErasures | None = None) -> None:
        self.cfg = cfg
        self.kiosk_id = kiosk_id
        self.bundles = bundles
        self.log = log
        self.monitor = monitor
        self.credentials = credentials
        self.overlay = overlay
        self.demo_mode = demo_mode
        self._client = client
        self._real = clock or (lambda: datetime.now(UTC))
        self._mono = mono or time.monotonic
        self._lock = threading.RLock()
        self._offset = timedelta(0)  # demo clock (DEMO_MODE=1 only)
        self._rng = rng or secrets.SystemRandom()
        self._random_challenge = "AUTO"
        self._force_next = False
        self.limiter = RateLimiter(cfg)
        self.sessions: dict[str, StepUpSession] = {}
        self._responses: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._closed: OrderedDict[str, str] = OrderedDict()
        self._events: deque[dict[str, Any]] = deque(maxlen=500)
        self._event_id = 0
        self._template_cache: dict[str, Any] = {"count": 0, "model": "unknown", "age_h": None}
        self.fallback_state = fallback_state if fallback_state is not None else InMemoryFallbackState()
        self.verifier = FallbackVerifier(cfg, self.fallback_state, totp_secret=credentials.totp_secret,
                                         card_pepper=card_pepper, bundle=lambda: self.bundles.lvb,
                                         card_revoked=overlay.card_revoked)
        self._erase_hooks: list[Callable[[str], Any]] = []
        self._erased: set[str] = set()  # erasures already applied locally in this process (TOTP + hooks)
        self._erase_lock = threading.Lock()  # one purge pass at a time (tick thread vs. feed pull)
        self._cloud_match: deque[tuple[datetime, bool]] = deque(maxlen=20)  # (real time, Rekognition ok)
        self.sync = SyncAgent(cfg, log, bundles, monitor, client=client, kiosk_id=kiosk_id, kiosk_key=kiosk_key,
                              overlay=overlay, clock=self.now, erasures=erasures, on_feed=self.apply_erasures)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.legacy_migration: dict[str, Any] | None = None  # from_env: orphaned decisions.sqlite report

    # ------------------------------------------------------------ construction
    @classmethod
    def from_env(cls, project_root: str | Path, *, env: Mapping[str, str] | None = None,
                 transport: httpx.BaseTransport | None = None,
                 clock: Callable[[], datetime] | None = None) -> PolicyRuntime:
        """`clock` = injected real (UTC) clock for tests (None = the system clock); it also drives the bundle
        store's refresh stamps and the connectivity monitor, so results never depend on the host time of day."""
        root = Path(project_root)
        e = dict(env) if env is not None else read_env(root)
        cfg = Thresholds.load(root / "config" / "thresholds.yaml")
        kiosk_id = e.get("KIOSK_ID") or ""
        if not kiosk_id:
            raise RuntimeError("KIOSK_ID is not set")
        data_key = e.get("EDGE_DATA_KEY") or ""
        if not data_key:
            raise RuntimeError("EDGE_DATA_KEY is not set (Fernet key, see .env.example)")
        data_dir = Path(e.get("EDGE_DATA_DIR") or (root / "edge" / "data"))
        data_dir.mkdir(parents=True, exist_ok=True)
        bundle_key = (e.get("SCHEDULE_BUNDLE_HMAC_KEY") or "").encode() or None
        bundles = BundleStore(Path(e.get("BUNDLE_PATH") or data_dir / "bundle.signed.json"), bundle_key, kiosk_id,
                              clock=clock)
        log = DecisionLog(data_dir / f"decisions_{kiosk_id}.sqlite", data_key, kiosk_id,
                          retention_hours=float(cfg.offline_store.max_retention_hours))
        fb_state = SqliteFallbackState(data_dir / "fallback_state.sqlite", data_key)  # device-wide
        # one-time: the pre-per-kiosk decisions.sqlite (unsynced records) -> per-kiosk queue, then archived 0600
        legacy = migrate_legacy_log(data_dir, data_key, log, fb_state, now=(clock or (lambda: datetime.now(UTC)))(),
                                    retention_hours=float(cfg.offline_store.max_retention_hours))
        url = (e.get("CLOUD_API_URL") or "").strip()
        kiosk_key = (e.get("KIOSK_HMAC_KEY") or "").encode() or None
        client = None
        if url:
            client = httpx.Client(base_url=url.rstrip("/"),
                                  timeout=float(cfg.connectivity.heartbeat_timeout_ms) / 1000.0,
                                  auth=KioskAuth(kiosk_id, kiosk_key or b"", e.get("CLOUD_API_KEY") or None),
                                  transport=transport)
        monitor = ConnectivityMonitor(cfg, configured=bool(url), forced_offline=_truthy(e.get("FORCE_OFFLINE")),
                                      **({"clock": clock} if clock else {}))
        pepper = (e.get("CARD_ID_PEPPER") or "").encode() or None
        rt = cls(cfg=cfg, kiosk_id=kiosk_id, bundles=bundles, log=log, monitor=monitor,
                 credentials=CredentialStore(data_dir / "credentials.enc", data_key),
                 overlay=RevocationOverlay(data_dir / "revocations.enc", data_key), card_pepper=pepper,
                 client=client, kiosk_key=kiosk_key, demo_mode=_truthy(e.get("DEMO_MODE")), fallback_state=fb_state,
                 clock=clock, erasures=PendingErasures(data_dir / "pending_erasures.enc", data_key))
        if legacy is not None:
            rt.legacy_migration = legacy
            rt._emit("ALERT_LEGACY_LOG_MIGRATION" if legacy.get("error") else "LEGACY_LOG_MIGRATED", **legacy)
            logger = logging.getLogger("edge.policy.runtime")  # `log` is the DecisionLog in this scope
            (logger.warning if legacy.get("error") else logger.info)("legacy decision log migration: %s", legacy)
        return rt

    # ------------------------------------------------------------ clocks / mode
    def real_now(self) -> datetime:
        return self._real()

    def now(self) -> datetime:
        """Edge wall clock: real time, shifted by the demo clock when DEMO_MODE=1."""
        return self._real() + self._offset

    def _ctx(self):
        return self.bundles.schedule_ctx(self.overlay.entries())

    def mode(self) -> str:
        """The mode the next attempt would use (stale online bundle -> OFFLINE, §8.1)."""
        if self.monitor.mode() != ONLINE:
            return OFFLINE
        return ONLINE if online_bundle_ok(self._ctx(), self.now(), self.cfg.for_mode(ONLINE)) else OFFLINE

    def bundle_kiosk_ids(self) -> set[str]:
        """Kiosk ids the verified LVB covers (in `kiosks` and, if present, in `scope.kiosk_ids`): the DEMO_MODE kiosk
        switch of edge/app.py allowed_kiosks(). Empty without a verified bundle (fail-secure)."""
        lvb = self.bundles.lvb or {}
        ids = set(lvb.get("kiosks") or {})
        scope = (lvb.get("scope") or {}).get("kiosk_ids")
        return ids & set(scope) if scope is not None else ids

    def kiosk_zone(self) -> str | None:
        return sched_mod.kiosk_zone(self.bundles.lvb, self.kiosk_id)

    def entitled_user_ids(self) -> set[str]:
        """Users entitled at this kiosk's zone (verified bundle + revocation feed) -> gallery filter."""
        lvb, zone = self.bundles.lvb, self.kiosk_zone()
        if not lvb or not zone:
            return set()
        merged = dict(lvb)
        merged["revocations"] = list(lvb.get("revocations") or []) + list(self.overlay.entries())
        return sched_mod.entitled_user_ids(merged, zone, self.now())

    def user_info(self, user_id: str) -> dict[str, Any] | None:
        """{"user_id", "display", "role"} from the verified bundle (for the kiosk / operator UI), else None."""
        display, role = user_meta(self.bundles.lvb, user_id)
        if display is None and role is None:
            return None
        return {"user_id": user_id, "display": display, "role": role}

    def revoked_user_ids(self) -> set[str]:
        return {r["user_id"] for r in self.overlay.entries()}

    def record_cloud_result(self, ok: bool) -> None:
        """A cloud call made outside decide() (e.g. email-OTP verify): failures count as heartbeat misses."""
        self.monitor.record(ok, "heartbeat_timeout" if ok else "match_timeout")

    def set_forced_mode(self, mode: str) -> dict[str, Any]:
        if mode not in ("OFFLINE", "AUTO"):
            raise ValueError("forced mode must be OFFLINE or AUTO")
        self.monitor.set_forced(mode == "OFFLINE")
        return self.mode_status()

    def set_random_challenge(self, mode: str) -> None:
        """Random liveness challenge control: AUTO (configured rate) | FORCE (every would-be ALLOW) |
        FORCE_NEXT (the next would-be ALLOW only) | OFF (never; eval/demo profile)."""
        if mode not in ("AUTO", "FORCE", "FORCE_NEXT", "OFF"):
            raise ValueError("random challenge mode must be AUTO, FORCE, FORCE_NEXT or OFF")
        self._random_challenge = mode
        self._force_next = mode == "FORCE_NEXT"

    def _attempt_rng(self) -> Any:
        if self._random_challenge == "OFF":
            return None
        if self._random_challenge == "FORCE":
            return _FixedRng(0.0)
        if self._force_next:
            def used() -> None:
                self._force_next = False
                self._random_challenge = "AUTO"
            return _FixedRng(0.0, on_use=used)
        return self._rng

    def set_demo_clock(self, *, set_local: str | None = None, offset_s: float | None = None,
                       reset: bool = False) -> dict[str, Any]:
        """POST /v1/admin/clock (DEMO_MODE=1 only, else PermissionError -> 403). Invalid input -> ValueError
        (-> 422) and the clock is left unchanged: "HH:MM" (today, IST) or an ISO datetime; the resulting offset
        must be finite and within +-MAX_DEMO_OFFSET_S (7 days) so now() can never overflow.
        "HH:MM" stays *today* (API.md 3.14, test X13): a time before the LVB issued_at - tolerance is a clock
        rollback (cache INVALID); the returned status flags it (`bundle_rollback`, `earliest_local`)."""
        if not self.demo_mode:
            raise PermissionError("demo clock requires DEMO_MODE=1")
        real = self._real()
        new = self._offset
        try:
            if reset:
                new = timedelta(0)
            elif set_local is not None:
                new = self._demo_target(str(set_local), real) - real
            elif offset_s is not None:
                off = float(offset_s)
                if not math.isfinite(off) or abs(off) > MAX_DEMO_OFFSET_S:
                    raise ValueError(f"offset_s must be finite and within +-{MAX_DEMO_OFFSET_S} s")
                new = timedelta(seconds=off)
            if abs(new.total_seconds()) > MAX_DEMO_OFFSET_S:
                raise ValueError(f"demo clock must stay within +-{MAX_DEMO_OFFSET_S // 86400} days of real time")
            _ = real + new  # must not overflow
        except (OverflowError, TypeError) as exc:
            raise ValueError(f"invalid demo clock value: {exc}") from exc
        with self._lock:
            self._offset = new
        return self._demo_clock_full()

    @staticmethod
    def _demo_target(set_local: str, real: datetime) -> datetime:
        m = _HHMM.match(set_local)
        if m:  # "HH:MM" today (IST)
            return real.astimezone(IST).replace(hour=int(m.group(1)), minute=int(m.group(2)), second=0,
                                                microsecond=0)
        if len(set_local) <= 5:
            raise ValueError("set_local must be HH:MM (00:00-23:59) or an ISO-8601 datetime")
        target = datetime.fromisoformat(set_local)  # ValueError on garbage
        return target.replace(tzinfo=IST) if target.tzinfo is None else target

    def _demo_clock_full(self) -> dict[str, Any]:
        now = self.now()
        out: dict[str, Any] = {"active": self._offset != timedelta(0),
                               "now_local": now.astimezone(IST).strftime("%H:%M"),
                               "now_utc": _iso(now), "offset_s": int(self._offset.total_seconds()),
                               "date_local": now.astimezone(IST).date().isoformat()}
        out.update(self._rollback_view(now))
        return out

    def _rollback_view(self, now: datetime) -> dict[str, Any]:
        """Control-panel warning (docs: the demo clock never re-signs): the earliest wall time the installed
        bundle accepts (issued_at - cache.clock_rollback_tolerance_s) and whether `now` is before it."""
        lvb = self.bundles.lvb
        issued = sched_mod.parse_ts(lvb.get("issued_at")) if lvb else None
        if issued is None:
            return {"bundle_issued_at": None, "earliest_utc": None, "earliest_local": None,
                    "earliest_date_local": None, "bundle_rollback": False, "cache_state": "INVALID"}
        earliest = issued - timedelta(seconds=float(self.cfg.cache.clock_rollback_tolerance_s))
        el = earliest.astimezone(IST)
        if el.second or el.microsecond:  # first whole minute a "HH:MM" demo time may use
            el = el.replace(second=0, microsecond=0) + timedelta(minutes=1)
        return {"bundle_issued_at": lvb.get("issued_at"), "earliest_utc": _iso(earliest),
                "earliest_local": el.strftime("%H:%M"), "earliest_date_local": el.date().isoformat(),
                "bundle_rollback": now < earliest,
                "cache_state": sched_mod.cache_state(lvb, True, now, self.cfg.cache)}

    def reset_rate_limit(self) -> None:
        self.limiter.reset()

    def set_template_cache_status(self, *, count: int, model: str, age_h: float | None) -> None:
        """edge-ml reports its template cache for GET /v1/mode (TemplateCacheStatus)."""
        self._template_cache = {"count": int(count), "model": str(model), "age_h": age_h}

    def provision_totp(self, user_id: str) -> str:
        """Enrolment helper: new TOTP secret for `user_id`; returns the otpauth URI (show once, never log)."""
        return self.credentials.provision_totp(user_id)

    def set_totp_secret(self, user_id: str, secret_b32: str) -> None:
        self.credentials.set_totp_secret(user_id, secret_b32)

    def totp_status(self, user_id: str) -> dict[str, Any]:
        """Enrolment UI: TOTP works only if the VERIFIED bundle marks the user `fallback.totp_enrolled` (the gate,
        set by the cloud on a confirmed enrolment) AND this edge holds the secret. bundle_enrolled None = the
        user is not in the bundle (or no bundle)."""
        u = ((self.bundles.lvb or {}).get("users") or {}).get(user_id)
        flag = bool(((u.get("fallback") or {}) if isinstance(u, Mapping) else {}).get("totp_enrolled")) \
            if isinstance(u, Mapping) else None
        cached = bool(self.credentials.totp_secret(user_id))
        return {"user_id": user_id, "bundle_enrolled": flag, "secret_cached": cached,
                "usable": bool(flag) and cached}

    def _local_methods(self, d: Decision) -> Decision:
        """Drop TOTP from a SECOND_FACTOR offer when this edge holds no TOTP secret for the candidate (the engine
        already filtered on the verified bundle). Only removes; never leaves the offer empty."""
        methods = d.next_action.methods
        if d.decision != STEP_UP or not methods or "TOTP" not in methods:
            return d
        uid = d.candidate_user_id
        if uid and self.credentials.totp_secret(uid):
            return d
        kept = tuple(m for m in methods if m != "TOTP")
        if not kept:
            return d
        return replace(d, next_action=replace(d.next_action, methods=kept))

    def access_users(self) -> dict[str, Any]:
        """Bundle-side view for GET /v1/admin/access/users (offline = this view only, read-only): every user of
        the VERIFIED bundle with role, zones, extra windows, validity, revocation, fallback enrolment flags
        (never the card hash) and the effective windows today at this kiosk's zone. Empty without a bundle."""
        lvb = self.bundles.lvb
        zone = self.kiosk_zone()
        base = {"bundle_version": self.bundles.version, "issued_at": (lvb or {}).get("issued_at"), "zone": zone,
                "roles": sorted((lvb or {}).get("roles") or {}), "zones": sorted((lvb or {}).get("zones") or {}),
                "users": []}
        if not lvb:
            return base
        now = self.now()
        today = now.astimezone(sched_mod._tz(lvb)).date()
        merged = dict(lvb)
        merged["revocations"] = list(lvb.get("revocations") or []) + list(self.overlay.entries())
        out = []
        for uid, u in sorted((lvb.get("users") or {}).items()):
            if not isinstance(u, Mapping):
                continue
            fb = u.get("fallback") if isinstance(u.get("fallback"), Mapping) else {}
            try:
                windows = sched_mod.day_windows(merged, uid, zone, today) if zone else []
            except (KeyError, ValueError, TypeError):
                windows = []
            out.append({
                "user_id": uid, "display": u.get("display"), "role": u.get("role"),
                "zones_add": list(u.get("zones_add") or []), "zones_remove": list(u.get("zones_remove") or []),
                "extra_windows": copy_windows(u.get("extra_windows")),
                "valid_from": u.get("valid_from"), "valid_until": u.get("valid_until"),
                "revoked": sched_mod.revoked_at_or_before(merged, uid, u, now),
                "totp_enrolled": bool(fb.get("totp_enrolled")),
                "card_enrolled": isinstance(fb.get("card_id_hash"), str) and bool(fb.get("card_id_hash")),
                "windows_today": windows,
            })
        base["users"] = out
        return base

    def refresh_bundle_now(self, *, expect_version: int | None = None) -> int:
        """POST /v1/admin/bundle/refresh: pull + verify + install the newest cloud bundle now; returns the installed
        bundle_version. Fail-secure: an unverifiable / older bundle never replaces the LVB. Raises
        CloudUnavailableError (-> 503) when the cloud is not configured, forced OFFLINE, unreachable, errors, has
        no bundle, the bundle is rejected, or (with `expect_version`) it does not yet serve that version."""
        if self._client is None:
            raise CloudUnavailableError("cloud not configured (CLOUD_API_URL empty)")
        if self.monitor.forced:
            raise CloudUnavailableError("forced OFFLINE")
        report: dict[str, Any] = {"bundle": None}
        prev = self.bundles.version
        with self.sync._lock:
            try:
                self.sync._pull_bundle(report)
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                self.monitor.record(False, "heartbeat_timeout")
                raise CloudUnavailableError(f"CLOUD_UNAVAILABLE: {type(exc).__name__}: {exc}", report) from exc
        self.monitor.record(True)
        status = str(report.get("bundle"))
        if status not in ("installed", "not_modified"):
            raise CloudUnavailableError(f"bundle refresh failed: {status}", report)
        version = self.bundles.version
        if version is None or (expect_version is not None and version < int(expect_version)):
            raise CloudUnavailableError(f"cloud has not served bundle >= {expect_version} yet (installed {version})",
                                        report)
        if version != prev:
            self._emit("BUNDLE_INSTALLED", version=version, previous=prev)
        return version

    # ------------------------------------------------------------ events
    def _emit(self, kind: str, **data: Any) -> None:
        self._event_id += 1
        self._events.append({"id": self._event_id, "type": kind, "at": _iso(self.now()), **data})

    def events(self, since_id: int = 0) -> list[dict[str, Any]]:
        """Policy events for GET /v1/events (e.g. ALERT_RATE_LIMIT_LOCKOUT, BUNDLE_REJECTED)."""
        return [e for e in list(self._events) if e["id"] > since_id]

    # ------------------------------------------------------------ decisions
    def _rebase_t0(self, signals: AttemptSignals) -> AttemptSignals:
        """Client t0 is untrusted: clamp its lag to [0, t0_max_lag] and re-base onto the edge wall clock."""
        lag = (self._real() - signals.t0).total_seconds()
        lag = min(max(lag, 0.0), float(self.cfg.latency_budget_ms.t0_max_lag) / 1000.0)
        return signals.model_copy(update={"t0": self.now() - timedelta(seconds=lag)})

    def _persist(self, d: Decision, wall: datetime) -> Decision:
        """Write the minimal record (P9). Failure -> DENY SYSTEM_ERROR (never an unlogged ALLOW)."""
        try:
            rec = minimal_record(d, int(self.cfg.offline_store.score_decimals))
            if d.decision == STEP_UP:  # not final yet: one chained record per attempt (no sync conflicts)
                self.log.put_pending(rec, wall)
            else:
                self.log.append_final(rec, created_real=self._real())
            return d
        except Exception as exc:  # noqa: BLE001
            err = replace(system_error(d, None, d.mode, wall, self.cfg, detail=f"log write failed: {exc}"),
                          zone=d.zone, t0=d.t0, bundle_version=d.bundle_version)
            try:
                self.log.append_final(minimal_record(err), created_real=self._real())
            except Exception:
                log.exception("decision log unavailable for attempt %s", d.attempt_id)
            return err

    def _rate_record(self, d: Decision) -> None:
        if self.limiter.record(d.decision, d.reason_codes, self._mono()):
            self._emit("ALERT_RATE_LIMIT_LOCKOUT", kiosk_id=self.kiosk_id, attempt_id=d.attempt_id)

    def _respond(self, d: Decision, t_start: float, latency_ms: Mapping[str, int] | None) -> dict[str, Any]:
        policy_ms = int((time.perf_counter() - t_start) * 1000)
        lat = {k: int(v) for k, v in (latency_ms or {}).items() if k in ("total", "liveness", "match", "schedule")}
        lat["policy"] = policy_ms
        lat["total"] = int(lat.get("total", 0)) + policy_ms
        body = d.to_response(lat)
        self._responses[d.attempt_id] = body
        self._responses.move_to_end(d.attempt_id)
        while len(self._responses) > 500:
            self._responses.popitem(last=False)
        if d.decision != STEP_UP:
            self._closed[d.attempt_id] = d.decision
            while len(self._closed) > 5000:
                self._closed.popitem(last=False)
        return body

    def decide(self, signals: AttemptSignals | Mapping[str, Any], latency_ms: Mapping[str, int] | None = None
               ) -> dict[str, Any]:
        t_start = time.perf_counter()
        with self._lock:
            wall, real = self.now(), self._real()
            mode = self.monitor.mode()
            if not isinstance(signals, AttemptSignals):
                try:
                    signals = AttemptSignals.model_validate(signals)
                except ValidationError as exc:
                    raw = signals if isinstance(signals, Mapping) else {}
                    stub = _Stub(attempt_id=str(raw.get("attempt_id") or f"att_invalid_{secrets.token_hex(6)}"),
                                 kiosk_id=self.kiosk_id, t0=wall)
                    d = system_error(stub, self._ctx(), mode, wall, self.cfg,
                                     detail=f"invalid signals: {exc.error_count()} errors")
                    return self._respond(self._persist(d, wall), t_start, latency_ms)
            aid = signals.attempt_id
            if aid in self._closed or self.log.has_final(aid):
                raise AttemptClosedError(aid)
            self.sessions.pop(aid, None)  # a new capture for an open attempt supersedes the old step-up
            signals = self._rebase_t0(signals)
            d = evaluate(signals, self._ctx(), mode, wall, cfg=self.cfg,
                         rate_limit_retry_s=self.limiter.retry_after_s(self._mono()), rng=self._attempt_rng())
            if d.cloud_miss:
                self.monitor.record(False, "match_timeout")  # P7: also a heartbeat miss
                self._cloud_match.append((real, False))
            elif d.mode == ONLINE and signals.cloud_match is not None and signals.cloud_match.ok:
                self.monitor.record(True)
                self._cloud_match.append((real, True))
            d = self._local_methods(d)
            if d.decision == STEP_UP and d.next_action.steps:
                T = self.cfg.for_mode(d.mode)
                ch = new_challenge(T, real) if "CHALLENGE" in d.next_action.steps else None
                session = open_session(d, real, self.cfg, ch)
                self.sessions[aid] = session
                d = session.last or d
            d = self._persist(d, wall)
            if d.decision == DENY:
                self.sessions.pop(aid, None)
            self._rate_record(d)
            return self._respond(d, t_start, latency_ms)

    def decide_error(self, attempt_id: str, *, detail: str | None = None,
                     latency_ms: Mapping[str, int] | None = None) -> dict[str, Any]:
        """For a perception-stage crash (e.g. PAD model exception, Q11): DENY + SYSTEM_ERROR, logged."""
        t_start = time.perf_counter()
        with self._lock:
            wall = self.now()
            if attempt_id in self._closed or self.log.has_final(attempt_id):
                raise AttemptClosedError(attempt_id)
            self.sessions.pop(attempt_id, None)
            stub = _Stub(attempt_id=attempt_id, kiosk_id=self.kiosk_id, t0=wall)
            d = system_error(stub, self._ctx(), self.mode(), wall, self.cfg, detail=detail)
            return self._respond(self._persist(d, wall), t_start, latency_ms)

    def _session(self, attempt_id: str) -> StepUpSession:
        s = self.sessions.get(attempt_id)
        if s is None:
            if attempt_id in self._closed or self.log.has_final(attempt_id):
                raise AttemptClosedError(attempt_id)
            raise AttemptNotFoundError(attempt_id)
        if s.status != OPEN:
            raise AttemptClosedError(attempt_id)
        return s

    def _finish_step(self, s2: StepUpSession, d: Decision, wall: datetime, t_start: float) -> dict[str, Any]:
        self.sessions[d.attempt_id] = s2
        d = self._persist(d, wall)
        if d.decision != STEP_UP:
            self.sessions.pop(d.attempt_id, None)
        self._rate_record(d)
        return self._respond(d, t_start, None)

    def resolve_challenge(self, attempt_id: str, evidence: ChallengeEvidence | Mapping[str, Any]) -> dict[str, Any]:
        t_start = time.perf_counter()
        with self._lock:
            wall, real = self.now(), self._real()
            s = self._session(attempt_id)
            ev = evidence if isinstance(evidence, ChallengeEvidence) else ChallengeEvidence.model_validate(evidence)
            T = self.cfg.for_mode(s.mode)
            try:
                s2, d = _resolve_challenge(s, ev, real, self.cfg, lambda n: new_challenge(T, n), wall_now=wall)
            except SessionClosed as exc:
                raise AttemptClosedError(attempt_id) from exc
            if d.detail:  # e.g. "TURN_LEFT: turned the wrong way (yaw delta -18.0 deg)" -- no biometric data
                log.info("challenge %s %s: %s", attempt_id, d.decision, d.detail)
            return self._finish_step(s2, d, wall, t_start)

    def resolve_fallback(self, attempt_id: str, submission: FallbackSubmission | Mapping[str, Any]) -> dict[str, Any]:
        t_start = time.perf_counter()
        with self._lock:
            wall, real = self.now(), self._real()
            s = self._session(attempt_id)
            sub = submission if isinstance(submission, FallbackSubmission) else \
                FallbackSubmission.model_validate(submission)
            try:
                s2, d = _resolve_fallback(s, sub, real, self.cfg, self.verifier, wall_now=wall)
            except SessionClosed as exc:
                raise AttemptClosedError(attempt_id) from exc
            return self._finish_step(s2, d, wall, t_start)

    def drop_method(self, attempt_id: str, method: str) -> dict[str, Any]:
        """Stop offering `method` on an open step-up (e.g. EMAIL_OTP when the cloud verify is down) and
        return the re-issued STEP_UP response. Counts nothing; attempts_left unchanged."""
        t_start = time.perf_counter()
        with self._lock:
            wall = self.now()
            s = self._session(attempt_id)
            try:
                s2, d = _drop_method(s, method, self.cfg, wall)
            except SessionClosed as exc:
                raise AttemptClosedError(attempt_id) from exc
            self.sessions[attempt_id] = s2
            d = self._persist(d, wall)  # STEP_UP -> refreshes the pending record (P9)
            return self._respond(d, t_start, None)

    def new_challenge(self) -> dict[str, Any]:
        """A fresh challenge (public view), e.g. for UI testing. Not bound to an attempt."""
        return new_challenge(self.cfg.for_mode(self.mode()), self._real()).public()

    def get_attempt(self, attempt_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._responses.get(attempt_id)

    # ------------------------------------------------------------ status / store / sync
    def mode_status(self) -> dict[str, Any]:
        st = self.monitor.status()
        wall = self.now()
        lvb = self.bundles.lvb
        eff = self.mode()
        if st["mode"] == ONLINE and eff == OFFLINE:
            st = {**st, "mode": OFFLINE, "state": OFFLINE, "reason": "bundle_stale"}
        T = self.cfg.for_mode(eff)
        cache = sched_mod.cache_state(lvb, True, wall, self.cfg.cache) if lvb else "INVALID"
        left = self.limiter.retry_after_int(self._mono())
        age = self.bundles.refresh_age_s()
        return {
            **st,
            "schedule_bundle": {
                "version": self.bundles.version,
                "issued_at": lvb.get("issued_at") if lvb else None,
                "expires_at": lvb.get("expires_at") if lvb else None,
                "signature_valid": lvb is not None,
                "cache_state": cache,
                "refresh_age_s": None if age is None else int(age),
                "rejected": self.bundles.alerts[-5:],
            },
            "revocation_seq": self.overlay.seq,
            "template_cache": dict(self._template_cache),
            "sync_queue_depth": self.log.queue_depth(),
            "demo_clock": self._demo_clock_full() if self.demo_mode else None,
            "kiosk_id": self.kiosk_id,
            "zone": self.kiosk_zone(),
            "policy_version": self.cfg.policy_version,
            "rate_limit": {"enabled": self.limiter.enabled, "locked": left is not None, "retry_after_s": left},
            "last_sync": {"at": _iso(self.sync.last_sync_at), "report": self.sync.last_report},
            "server_flags": self.sync.flags[-20:],
            "random_challenge": self._random_challenge,
            "policy_bars": self._policy_bars(T, eff),
            "cloud_match": self._cloud_match_status(),
        }

    def _cloud_match_status(self) -> dict[str, Any]:
        """P7 visibility: a Rekognition miss makes that ATTEMPT offline while heartbeats keep the kiosk ONLINE.
        `degraded` = the latest online attempt fell back to an offline decision (kiosk can explain the badge)."""
        cm = list(self._cloud_match)
        misses = [t for t, ok in cm if not ok]
        oks = [t for t, ok in cm if ok]
        return {"enabled": bool(self.cfg.match.rekognition.enabled), "recent": len(cm), "misses": len(misses),
                "last_miss_at": _iso(max(misses)) if misses else None, "last_ok_at": _iso(max(oks)) if oks else None,
                "degraded": bool(cm) and not cm[-1][1]}

    # ------------------------------------------------------------ local erasure (DPDP)
    def add_erase_hook(self, fn: Callable[[str], Any]) -> None:
        """Register a callback run once per user with an ERASED revocation (bundle or feed), e.g. edge-ml's
        template-store delete. Replayed for users already erased before the hook was registered."""
        with self._lock:
            self._erase_hooks.append(fn)
            done = sorted(self._erased)
        for uid in done:
            self._run_erase_hook(fn, uid)

    def _run_erase_hook(self, fn: Callable[[str], Any], uid: str) -> None:
        try:
            fn(uid)
        except Exception as exc:  # noqa: BLE001 - one failing hook must not stop the others / the tick
            log.error("erase hook failed for a user (%s)", type(exc).__name__)

    def erased_user_ids(self) -> set[str]:
        """Users currently suspended by a DPDP erasure: an ERASED revocation of the verified bundle or an ERASE
        feed event not yet lifted by a READMIT (docs/API.md §4.3)."""
        lvb = self.bundles.lvb or {}
        return {str(r.get("user_id")) for r in lvb.get("revocations") or []
                if isinstance(r, Mapping) and r.get("reason") == "ERASED" and r.get("user_id")} \
            | self.overlay.erased_users()

    def apply_erasures(self) -> list[str]:
        """DPDP erasure, local side: drop the user's TOTP secret and run the erase hooks (templates), once per
        erasure. Sources: ERASED revocations of the verified bundle, ERASE feed events (overlay erasure state) and
        the overlay's durable purge list (one entry per ERASE event, so an ERASE followed by a READMIT in the same
        pull still purges the pre-erasure data). The once-per-user marker is dropped when the erasure is lifted
        (bundle no longer lists it / READMIT), so a later erasure purges again. Runs after every feed pull and at
        every tick."""
        with self._erase_lock:
            suspended = self.erased_user_ids()
            queued = self.overlay.pending_purge()
            with self._lock:
                self._erased &= suspended  # lifted erasures: forget the marker
                todo = sorted((suspended | set(queued)) - self._erased)
                hooks = list(self._erase_hooks)
            for uid in todo:
                self.credentials.remove(uid)
                for fn in hooks:
                    self._run_erase_hook(fn, uid)
                with self._lock:
                    if uid in suspended:
                        self._erased.add(uid)
                    self._emit("USER_ERASED_LOCAL", user_id=uid)
            if queued:
                self.overlay.purged(queued)
            return todo

    def reinstate_user(self, user_id: str) -> bool:
        """Re-enrolment of a re-admitted user (edge-ml enroll, after the bundle no longer carries the erasure): drop
        only the overlay's erasure state for `user_id` (and a purge that has not run yet) and the once-per-user
        marker. ADMIN / security revocations stay. Returns True if erasure state was removed."""
        with self._erase_lock:
            had = self.overlay.reinstate(user_id)
            with self._lock:
                self._erased.discard(user_id)
            if had:
                self._emit("USER_REINSTATED_LOCAL", user_id=user_id)
            return had

    # ------------------------------------------------------------ pending cloud erasures (R-J)
    def queue_cloud_erasure(self, user_id: str) -> dict[str, str]:
        """DELETE /v1/enroll/{user_id} could not reach the cloud (OFFLINE / transport / non-2xx): persist the cloud
        erasure (user_id + queued_at only, encrypted) for replay at every sync. Idempotent. ValueError on an
        invalid user_id (^u_[0-9a-z]{4}$)."""
        out = self.sync.erasures.add(user_id, self._real())
        self._emit("CLOUD_ERASURE_QUEUED", user_id=out["user_id"])
        return out

    def pending_cloud_erasures(self) -> list[dict[str, str]]:
        """[{user_id, queued_at}] still waiting for the cloud (GET /v1/admin/access/users pending_cloud_erasures)."""
        return self.sync.erasures.items()

    def replay_cloud_erasures(self) -> dict[str, Any]:
        """Flush the pending cloud erasures now ({done, failed, pending}); also runs inside every sync cycle.
        CloudUnavailableError when not configured, forced OFFLINE or unreachable (entries stay queued)."""
        if self._client is None:
            raise CloudUnavailableError("cloud not configured (CLOUD_API_URL empty)")
        if self.monitor.forced:
            raise CloudUnavailableError("forced OFFLINE")
        try:
            out = self.sync.replay_erasures()
        except httpx.HTTPError as exc:
            self.monitor.record(False, "heartbeat_timeout")
            raise CloudUnavailableError(f"CLOUD_UNAVAILABLE: {type(exc).__name__}: {exc}") from exc
        self.monitor.record(True)
        for uid in out["done"]:
            self._emit("CLOUD_ERASURE_DONE", user_id=uid)
        return out

    def _policy_bars(self, T: Thresholds, eff: str) -> dict[str, Any]:
        """The bars the engine applies in the effective mode. Identity: Rekognition online when enabled,
        otherwise the local matcher with the OFFLINE bars (engine stage 4), so report those."""
        rek = eff == ONLINE and bool(T.match.rekognition.enabled)
        MB = (T if rek else self.cfg.for_mode(OFFLINE)).match.local
        L = T.liveness
        return {
            "pad_pass": L.pad.pass_min, "flash_pass_r": L.flash.pass_min_r,
            "match_allow": MB.allow_min_cosine, "match_margin": MB.min_margin_top1_top2,
            "random_rate": T.challenge.random_rate,
            "ambient_exception": bool(L.flash.ambient_exception_enabled) and eff == ONLINE,
            "moire_unsure": L.moire.unsure_score, "device_unsure": L.device_detector.unsure_conf,
            "flash_enforce": enforced(L.flash), "moire_enforce": enforced(L.moire),
            "m2_rgb_enforce": enforced(L.mask, "m2_rgb_enforce"), "rekognition": rek,
            "rekognition_timeout_ms": T.latency_budget_ms.rekognition_timeout,
            "rekognition_probe_deadline_ms": T.latency_budget_ms.rekognition_probe_deadline,
        }

    def store_view(self) -> dict[str, Any]:
        """GET /v1/admin/store (SC2d demo): exactly what is stored, decrypted minimal records."""
        with self._lock:
            ok, bad = self.log.verify_chain()
            try:
                db_bytes = os.path.getsize(self.log.path)
            except OSError:
                db_bytes = None
            return {
                "records": self.log.records(),
                "queue_depth": self.log.queue_depth(),
                "tombstones": self.log.tombstones(),
                "chain_head": self.log.chain_head(),
                "db_bytes": db_bytes,
                "never_stored": list(NEVER_STORED),
                "pending": self.log.pending(),
                "chain_ok": ok,
                "chain_bad_seq": bad,
                "fields": list(RECORD_FIELDS),
                "encryption": "AES-256-GCM (HKDF from EDGE_DATA_KEY), per-row AAD kiosk|seq|attempt",
                "retention_hours": float(self.cfg.offline_store.max_retention_hours),
            }

    def sync_now(self) -> dict[str, Any]:
        """POST /v1/admin/sync. Raises CloudUnavailableError (-> 503) when the cloud cannot be used."""
        if self._client is None:
            raise CloudUnavailableError("cloud not configured (CLOUD_API_URL empty)")
        if self.monitor.forced:
            raise CloudUnavailableError("forced OFFLINE")
        report = self.sync.run_once()
        if report.get("error"):
            raise CloudUnavailableError(str(report["error"]), report)
        return report

    # ------------------------------------------------------------ background work
    def tick(self) -> None:
        """One maintenance pass: retention purge, abandoned step-ups, stale pending records."""
        wall, real = self.now(), self._real()
        self.apply_erasures()
        with self._lock:
            self.log.purge_expired(real)  # retention is real elapsed time, never the demo clock
            T_totp = self.cfg.fallback.totp
            self.fallback_state.purge_totp_before(
                int(real.timestamp()) // int(T_totp.period_s) - int(T_totp.window_steps) - 1)
            for aid, s in list(self.sessions.items()):
                res = expire_if_due(s, real)
                if res is not None:
                    _, last = res
                    try:
                        self.log.append_final(minimal_record(last), created_real=real)
                    except Exception:  # noqa: BLE001 - already final
                        log.debug("abandoned step-up %s already final", aid)
                    self.sessions.pop(aid, None)
                    self._closed[aid] = last.decision
            ttl = timedelta(seconds=float(self.cfg.stepup.session_ttl_s) + 60)
            for rec in self.log.stale_pending(wall - ttl):
                if rec["attempt_id"] not in self.sessions:
                    try:
                        self.log.append_final(rec, created_real=self._real())
                    except Exception:  # noqa: BLE001 - already final
                        log.debug("stale pending record %s already final", rec["attempt_id"])

    def heartbeat(self) -> bool:
        """GET {CLOUD_API_URL}/v1/health; keeps running while forced (AUTO -> SYNCING needs fresh results).
        On success (not forced) also pulls the revocation feed (§5.1: every heartbeat)."""
        if self._client is None:
            self.monitor.record(False, "not_configured")
            return False
        try:
            r = self._client.get(str(self.cfg.connectivity.health_path), auth=None)
            ok = r.status_code == 200
        except httpx.HTTPError:
            ok = False
        self.monitor.record(ok)
        if ok and not self.monitor.forced:
            try:
                newly = self.sync.pull_revocations()
                for uid in newly:
                    self._emit("REVOCATION_APPLIED", user_id=uid)
            except (httpx.HTTPError, ValueError, KeyError):
                pass
        return ok

    def _loop(self) -> None:
        C, S = self.cfg.connectivity, self.cfg.sync
        next_hb = next_tick = next_sync = 0.0
        backoff = float(S.backoff_initial_s)
        refresh_s = float(self.cfg.cache.bundle_refresh_interval_min) * 60
        last_refresh = 0.0
        while not self._stop.is_set():
            t = time.monotonic()
            try:
                if t >= next_hb:
                    self.heartbeat()
                    next_hb = t + float(C.heartbeat_interval_s)
                if t >= next_tick:
                    self.tick()
                    next_tick = t + 15
                state = self.monitor.state
                due = state == SYNCING or (state == ONLINE and (self.log.queue_depth() > 0
                                                                or len(self.sync.erasures) > 0  # R-J replay
                                                                or t - last_refresh > refresh_s))
                if self._client is not None and not self.monitor.forced and due and t >= next_sync:
                    rep = self.sync.run_once()
                    if rep.get("error"):
                        jitter = 1 + float(S.backoff_jitter) * (2 * self._rng.random() - 1)
                        next_sync = t + backoff * jitter
                        backoff = min(backoff * 2, float(S.backoff_max_s))
                    else:
                        backoff, next_sync, last_refresh = float(S.backoff_initial_s), t + 2, t
            except Exception:  # noqa: BLE001 - the background loop must never die
                next_sync = t + backoff
            self._stop.wait(0.5)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="policy-runtime", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        self._thread = None


def copy_windows(extra: Any) -> dict[str, list[dict[str, Any]]]:
    """Plain-JSON copy of users[].extra_windows ({ZONE: [{days, start, end}]}); malformed entries dropped."""
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(extra, Mapping):
        return out
    for z, ws in extra.items():
        if isinstance(ws, list):
            out[str(z)] = [{k: (list(w[k]) if k == "days" and w.get(k) is not None else w.get(k))
                            for k in ("days", "start", "end")} for w in ws if isinstance(w, Mapping)]
    return out


class _Stub:
    """Minimal attribute bag for system_error() when the input could not be parsed."""

    def __init__(self, attempt_id: str, kiosk_id: str, t0: datetime | None = None) -> None:
        self.attempt_id, self.kiosk_id, self.t0 = attempt_id, kiosk_id, t0


__all__ = [
    "OFFLINE",
    "ONLINE",
    "SYNCING",
    "AttemptClosedError",
    "AttemptNotFoundError",
    "CloudUnavailableError",
    "PolicyRuntime",
]
