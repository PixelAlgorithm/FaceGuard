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
record stamps; the real clock drives step-up / nonce TTLs, TOTP, second-factor lockouts, the forced-mode deadline
and the rate limiter (monotonic).
Hardening (policy-fixes): forced OFFLINE auto-reverts (set_forced_mode), the deny-only revocation feed is pulled
even while forced, every background stage is isolated (F07), a user revoked while a step-up is open is denied
(F11), an erasure is complete only when every hook succeeded (EO-05), alerts are listed by recent_alerts (F14),
GET /v1/mode carries counts only (sync_detail() has the ids), a deleted fallback-state file is detected and
re-seeded from the decision log (EO-12).
Layout (behaviour-identical split, quality bar <= 800 lines): this module keeps construction, clocks, mode, the
decision path and sync_now; PolicyRuntime mixes in runtime_clock (forced mode, random challenge, demo clock),
runtime_erasure (local DPDP erasure, pending cloud erasures / enrolments, sync + reconcile hooks), runtime_views
(GET /v1/mode, access / store views) and runtime_background (tick, heartbeat, loop thread). Shared names live in
runtime_common; every public name (PolicyRuntime, the exceptions, read_env, copy_windows, IST, NEVER_STORED,
MAX_DEMO_OFFSET_S, TICK_INTERVAL_S) stays importable from edge.policy.runtime.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from edge.config import cloud_tls_verify, validate_cloud_url
from edge.offline.bundle import DEFAULT_KEY_ID, BundleStore
from edge.offline.connectivity import OFFLINE, ONLINE, SYNCING, ConnectivityMonitor
from edge.offline.credentials import CredentialStore
from edge.offline.erasures import PendingEnrolments, PendingErasures, valid_actor
from edge.offline.migrate import migrate_legacy_log, purge_foreign_logs
from edge.offline.signing import KioskAuth
from edge.offline.store import DecisionLog, SqliteFallbackState, minimal_record, reseed_fallback_state
from edge.offline.sync import RevocationOverlay, SyncAgent
from edge.policy import runtime_ops as ops
from edge.policy import schedule as sched_mod
from edge.policy.challenge import new_challenge
from edge.policy.codes import order_codes
from edge.policy.engine import (
    ALLOW,
    DENY,
    GENERIC_DESK_MESSAGE,
    STEP_UP,
    Decision,
    NextAction,
    evaluate,
    online_bundle_ok,
    system_error,
    user_meta,
)
from edge.policy.fallback import FallbackVerifier, InMemoryFallbackState
from edge.policy.ratelimit import RateLimiter
from edge.policy.runtime_background import TICK_INTERVAL_S, BackgroundMixin
from edge.policy.runtime_clock import MAX_DEMO_OFFSET_S, ClockMixin
from edge.policy.runtime_common import IST, AttemptClosedError, AttemptNotFoundError, CloudUnavailableError
from edge.policy.runtime_common import iso as _iso
from edge.policy.runtime_erasure import ErasureMixin
from edge.policy.runtime_views import NEVER_STORED, ViewsMixin, copy_windows
from edge.policy.signals import AttemptSignals, ChallengeEvidence, FallbackSubmission
from edge.policy.stepup import OPEN, SessionClosed, StepUpSession, open_session
from edge.policy.stepup import drop_method as _drop_method
from edge.policy.stepup import resolve_challenge as _resolve_challenge
from edge.policy.stepup import resolve_fallback as _resolve_fallback
from edge.policy.thresholds import Thresholds

log = logging.getLogger("edge.policy.runtime")  # never logs secrets, codes or biometric data
ENV_KEYS = ("KIOSK_ID", "EDGE_DATA_KEY", "SCHEDULE_BUNDLE_HMAC_KEY", "CARD_ID_PEPPER", "KIOSK_HMAC_KEY",
            "CLOUD_API_URL", "CLOUD_API_KEY", "FORCE_OFFLINE", "DEMO_MODE", "EDGE_DATA_DIR", "BUNDLE_PATH",
            "SCHEDULE_BUNDLE_KEY_ID", "CLOUD_TLS_CA_FILE")


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


class PolicyRuntime(ClockMixin, ErasureMixin, ViewsMixin, BackgroundMixin):
    def __init__(self, *, cfg: Thresholds, kiosk_id: str, bundles: BundleStore, log: DecisionLog,
                 monitor: ConnectivityMonitor, credentials: CredentialStore, overlay: RevocationOverlay,
                 card_pepper: bytes | None, client: httpx.Client | None = None, kiosk_key: bytes | None = None,
                 demo_mode: bool = False, rng: Any = None, fallback_state: Any = None,
                 clock: Callable[[], datetime] | None = None, mono: Callable[[], float] | None = None,
                 erasures: PendingErasures | None = None, enrolments: PendingEnrolments | None = None,
                 data_dir: Path | None = None, data_key: str | None = None) -> None:
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
        self._alerts = ops.AlertLog(self.now, _iso)  # F14: thread-safe (request + loop threads)
        self._forced = ops.ForcedState(forced=bool(monitor.forced))  # env FORCE_OFFLINE: unlimited
        self._template_cache: dict[str, Any] = {"count": 0, "model": "unknown", "age_h": None}
        self.fallback_state = fallback_state if fallback_state is not None else InMemoryFallbackState()
        self.verifier = FallbackVerifier(cfg, self.fallback_state, totp_secret=credentials.totp_secret,
                                         card_pepper=card_pepper, bundle=self._decision_bundle,
                                         card_revoked=overlay.card_revoked, on_lockout=self._on_lockout)
        self._erase_hooks: list[Callable[[str], Any]] = []
        self._sync_hooks: list[Callable[[], Any]] = []
        self._reconcile_hooks: list[Callable[[datetime], Any]] = []
        self._erased: set[str] = set()  # erasures already applied locally in this process (TOTP + hooks)
        self._erase_failed: set[str] = set()  # EO-05: a hook / TOTP removal failed -> retried every tick
        self.enrolments = enrolments if enrolments is not None else PendingEnrolments(None, None)
        self._data_dir, self._data_key = data_dir, data_key
        self._orphan_seen: dict[str, tuple[Any, Any, Any]] = {}  # P2: ALERT_ORPHANED_QUEUE once per state change
        self._pre_sync_hooks: list[Callable[[], Any]] = []
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
        demo = _truthy(e.get("DEMO_MODE"))
        bundles = BundleStore(Path(e.get("BUNDLE_PATH") or data_dir / "bundle.signed.json"), bundle_key, kiosk_id,
                              clock=clock, key_id=e.get("SCHEDULE_BUNDLE_KEY_ID") or DEFAULT_KEY_ID,
                              allow_documented_codes=demo)  # EO-02 key-id pin, EO-10 documented codes
        log = DecisionLog(data_dir / f"decisions_{kiosk_id}.sqlite", data_key, kiosk_id,
                          retention_hours=float(cfg.offline_store.max_retention_hours))
        fb_state = SqliteFallbackState(data_dir / "fallback_state.sqlite", data_key)  # device-wide
        # one-time: the pre-per-kiosk decisions.sqlite (unsynced records) -> per-kiosk queue, then archived 0600
        legacy = migrate_legacy_log(data_dir, data_key, log, fb_state, now=(clock or (lambda: datetime.now(UTC)))(),
                                    retention_hours=float(cfg.offline_store.max_retention_hours))
        # EAE-07: https only (loopback / DEMO_MODE=1 excepted) + optional pinned CA, same rules as edge/config.py
        url = validate_cloud_url(e.get("CLOUD_API_URL") or "", demo_mode=demo)
        kiosk_key = (e.get("KIOSK_HMAC_KEY") or "").encode() or None
        client = None
        if url:
            client = httpx.Client(base_url=url,
                                  timeout=float(cfg.connectivity.heartbeat_timeout_ms) / 1000.0,
                                  auth=KioskAuth(kiosk_id, kiosk_key or b"", e.get("CLOUD_API_KEY") or None),
                                  transport=transport, verify=cloud_tls_verify(e.get("CLOUD_TLS_CA_FILE") or ""))
        monitor = ConnectivityMonitor(cfg, configured=bool(url), forced_offline=_truthy(e.get("FORCE_OFFLINE")),
                                      **({"clock": clock} if clock else {}))
        pepper = (e.get("CARD_ID_PEPPER") or "").encode() or None
        erasures = PendingErasures(data_dir / "pending_erasures.enc", data_key)
        enrolments = PendingEnrolments(data_dir / "pending_enrolments.enc", data_key)
        credentials = CredentialStore(data_dir / "credentials.enc", data_key)
        rt = cls(cfg=cfg, kiosk_id=kiosk_id, bundles=bundles, log=log, monitor=monitor, credentials=credentials,
                 overlay=RevocationOverlay(data_dir / "revocations.enc", data_key), card_pepper=pepper,
                 client=client, kiosk_key=kiosk_key, demo_mode=demo, fallback_state=fb_state,
                 clock=clock, erasures=erasures, enrolments=enrolments, data_dir=data_dir, data_key=data_key)
        rt._check_fallback_state(fb_state)
        if getattr(log, "evidence_rebased", False):  # EO-06: deletion evidence missing (upgrade or tampering)
            rt._emit("ALERT_LOG_EVIDENCE_REBASED", kiosk_id=kiosk_id)
        for name, store in (("pending_erasures", erasures), ("pending_enrolments", enrolments),
                            ("credentials", credentials)):
            if getattr(store, "corrupt", None) is not None:  # EO-08: quarantined, degraded, never fatal
                rt._emit("ALERT_STATE_FILE_QUARANTINED", file=name)
        rt._purge_foreign_logs()
        if legacy is not None:
            rt.legacy_migration = legacy
            rt._emit("ALERT_LEGACY_LOG_MIGRATION" if legacy.get("error") else "LEGACY_LOG_MIGRATED", **legacy)
            logger = logging.getLogger("edge.policy.runtime")  # `log` is the DecisionLog in this scope
            (logger.warning if legacy.get("error") else logger.info)("legacy decision log migration: %s", legacy)
        return rt

    def _check_fallback_state(self, fb: Any) -> None:
        """EO-12: a deleted / replaced fallback_state.sqlite (new epoch while the log knows another) is an alert;
        consumed codes and TOTP steps are always re-seeded from the decision log (tighten-only)."""
        epoch = getattr(fb, "epoch", None)
        if not isinstance(epoch, str):
            return
        known = self.log.fallback_epoch()
        seeded = reseed_fallback_state(fb, self.log, self._real())
        if known is not None and known != epoch:
            self._emit("ALERT_FALLBACK_STATE_RESET", **seeded)
        elif seeded["codes"] or seeded["totp_steps"]:
            self._emit("FALLBACK_STATE_RESEEDED", **seeded)
        self.log.set_fallback_epoch(epoch)

    def _purge_foreign_logs(self) -> None:
        """EO-07: retention for per-kiosk logs of other KIOSK_IDs on this device + an alert while they hold data."""
        if self._data_dir is None or not self._data_key:
            return
        try:
            report = purge_foreign_logs(self._data_dir, self._data_key, self.kiosk_id, now=self._real(),
                                        retention_hours=float(self.cfg.offline_store.max_retention_hours))
        except Exception as exc:  # noqa: BLE001 - maintenance must never stop the runtime
            log.error("foreign log purge failed (%s)", type(exc).__name__)
            return
        current: dict[str, tuple[Any, Any, Any]] = {}
        for entry in report:
            if not (entry.get("queued") or entry.get("tombstones") or entry.get("error")):
                continue
            key = str(entry.get("file") or entry.get("kiosk_id"))
            state = (entry.get("queued"), entry.get("tombstones"), entry.get("error"))
            current[key] = state
            if self._orphan_seen.get(key) != state:  # P2: alert once per (file, state), never every tick
                self._emit("ALERT_ORPHANED_QUEUE", kiosk_id=entry.get("kiosk_id"), queued=state[0],
                           tombstones=state[1], error=state[2])
        self._orphan_seen = current

    def _decision_bundle(self) -> Mapping[str, Any] | None:
        """The verified bundle as decisions use it (EO-10: documented fixture codes dropped unless DEMO_MODE=1)."""
        if hasattr(self.bundles, "decision_bundle"):
            return self.bundles.decision_bundle
        return self.bundles.lvb

    def _on_lockout(self, kind: str, subject: str | None) -> None:
        self._emit("ALERT_FALLBACK_LOCKOUT", lock=kind, subject=subject, kiosk_id=self.kiosk_id)

    # ------------------------------------------------------------ clocks / mode
    def real_now(self) -> datetime:
        return self._real()

    def now(self) -> datetime:
        """Edge wall clock: real time, shifted by the demo clock when DEMO_MODE=1."""
        return self._real() + self._offset

    def _ctx(self):
        ctx = self.bundles.schedule_ctx(self.overlay.entries())
        if getattr(self.overlay, "state_lost", False):  # EO-08: feed revocations may be missing
            ctx = replace(ctx, revocations_incomplete=True)
        return ctx

    def mode(self) -> str:
        """The mode the next attempt would use (stale online bundle -> OFFLINE, §8.1)."""
        self._expire_forced()
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
        return sched_mod.entitled_user_ids(merged, zone, self.now(), revocation_slack_s=self._revocation_slack_s())

    def _revocation_slack_s(self) -> float:
        return float(self.cfg.cache.clock_rollback_tolerance_s)  # F03: same bound as the rollback tolerance

    def _merged_bundle(self) -> dict[str, Any]:
        lvb = self.bundles.lvb or {}
        merged = dict(lvb)
        merged["revocations"] = list(lvb.get("revocations") or []) + list(self.overlay.entries())
        return merged

    def is_revoked_now(self, user_id: str) -> bool:
        """Deny-only live check: ANY revocation the edge holds for `user_id` (bundle, user flag or feed), whatever
        its revoked_at (F11 / F03). Fail-secure: no verified bundle -> only the feed counts."""
        merged = self._merged_bundle()
        u = (merged.get("users") or {}).get(user_id)
        return sched_mod.revoked_any(merged, user_id, u if isinstance(u, Mapping) else None)

    def excluded_user_ids(self) -> set[str]:
        """Users the local matcher must never return (F12 full-gallery search): DPDP-erased or erase-pending users
        (bundle ERASED, feed ERASE not lifted, queued purge, failed local purge)."""
        return self.erased_user_ids() | set(self.overlay.pending_purge()) | set(self._erase_failed)

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
                self.sync._pull_bundle(report, force=True)  # no If-None-Match: renews issued_at (SC2-D2)
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
        self._after_sync({"bundle": status})
        return version

    # ------------------------------------------------------------ events
    def _emit(self, kind: str, **data: Any) -> None:
        self._alerts.emit(kind, **data)

    def events(self, since_id: int = 0) -> list[dict[str, Any]]:
        """Policy events (e.g. ALERT_RATE_LIMIT_LOCKOUT, ALERT_FALLBACK_LOCKOUT), oldest first. Thread-safe."""
        return self._alerts.since(since_id)

    def recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """F14: newest `limit` (1..200) ALERT_* + security events, oldest first, for an authenticated route."""
        return self._alerts.recent_alerts(limit)

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
        self._expire_forced()  # a forced OFFLINE past its deadline reverts before this attempt
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

    def _revoked_before_allow(self, d: Decision) -> Decision:
        """F11: a USER revocation received while the step-up was open denies (deny-only, any revoked_at)."""
        uid = d.candidate_user_id
        if d.decision != ALLOW or not uid or not self.is_revoked_now(uid):
            return d
        codes = ["SCHEDULE_REVOKED"] + (["OFFLINE_MODE"] if d.mode == OFFLINE else [])
        return replace(d, decision=DENY, reason_codes=tuple(order_codes(codes)), resolved_codes=(),
                       next_action=NextAction("CONTACT_DESK"), stage="schedule", schedule_result="REVOKED",
                       display_message=GENERIC_DESK_MESSAGE)

    def _finish_step(self, s2: StepUpSession, d: Decision, wall: datetime, t_start: float) -> dict[str, Any]:
        d = self._revoked_before_allow(d)
        if d.decision == DENY:
            s2 = replace(s2, status="DENIED", last=d)
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
            if self._email_otp_unverifiable(s, sub):  # F10 / R11: drop the method, count nothing
                self.monitor.record(False, "match_timeout")
                return self.drop_method(attempt_id, "EMAIL_OTP")
            try:
                s2, d = _resolve_fallback(s, sub, real, self.cfg, self.verifier, wall_now=wall)
            except SessionClosed as exc:
                raise AttemptClosedError(attempt_id) from exc
            return self._finish_step(s2, d, wall, t_start)

    def _email_otp_unverifiable(self, s: StepUpSession, sub: FallbackSubmission) -> bool:
        """An ONLINE session's EMAIL_OTP submission that could not be cloud-verified (verified is None) because the
        edge is no longer ONLINE: R11 drop instead of a counted failure. Never when it is the last method."""
        return (sub.method == "EMAIL_OTP" and sub.email_otp_verified is None and s.mode == ONLINE
                and "EMAIL_OTP" in s.methods and len(s.methods) > 1 and self.mode() != ONLINE)

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

    # ------------------------------------------------------------ pending cloud erasures (R-J)
    # Defined here, not in ErasureMixin: callers / tests feature-detect it on the class (delattr -> "no queue").
    def queue_cloud_erasure(self, user_id: str, actor: str | None = None) -> dict[str, Any]:
        """DELETE /v1/enroll/{user_id} could not reach the cloud (OFFLINE / transport / non-2xx): persist the cloud
        erasure (user_id, queued_at, actor; encrypted) for replay at every sync (DELETE ...?actor=). Idempotent.
        ValueError on an invalid user_id (^u_[0-9a-z]{4}$) or actor (staff:<id> | key:<id> | legacy:admin_token)."""
        out = self.sync.erasures.add(user_id, self._real(), actor=valid_actor(actor))
        self._emit("CLOUD_ERASURE_QUEUED", user_id=out["user_id"], actor=out.get("actor"))
        return out

    # ------------------------------------------------------------ status / store / sync
    def sync_now(self) -> dict[str, Any]:
        """POST /v1/admin/sync. Raises CloudUnavailableError (-> 503) when the cloud cannot be used."""
        if self._client is None:
            raise CloudUnavailableError("cloud not configured (CLOUD_API_URL empty)")
        if self.monitor.forced:
            raise CloudUnavailableError("forced OFFLINE")
        self._before_sync()
        report = self.sync.run_once()
        if report.get("error"):
            raise CloudUnavailableError(str(report["error"]), report)
        self._after_sync(report)
        return report


class _Stub:
    """Minimal attribute bag for system_error() when the input could not be parsed."""

    def __init__(self, attempt_id: str, kiosk_id: str, t0: datetime | None = None) -> None:
        self.attempt_id, self.kiosk_id, self.t0 = attempt_id, kiosk_id, t0


__all__ = [
    "IST",
    "MAX_DEMO_OFFSET_S",
    "NEVER_STORED",
    "OFFLINE",
    "ONLINE",
    "SYNCING",
    "TICK_INTERVAL_S",
    "AttemptClosedError",
    "AttemptNotFoundError",
    "CloudUnavailableError",
    "PolicyRuntime",
    "copy_windows",
    "read_env",
]
