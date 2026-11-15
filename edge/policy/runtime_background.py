"""PolicyRuntime mixin (edge/policy/runtime.py): background work. One maintenance tick (forced-mode expiry, local
erasures, retention purge, abandoned step-ups, consumed codes, foreign-kiosk logs), the cloud heartbeat (pulls the
deny-only revocation feed, even while forced OFFLINE) and the loop thread. Every stage is isolated (F07): one
failure never blocks the others and the loop never dies."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx

from edge.offline.connectivity import ONLINE, SYNCING
from edge.offline.store import minimal_record
from edge.policy.stepup import StepUpSession, expire_if_due

if TYPE_CHECKING:
    from edge.offline.bundle import BundleStore
    from edge.offline.connectivity import ConnectivityMonitor
    from edge.offline.store import DecisionLog
    from edge.offline.sync import SyncAgent
    from edge.policy.thresholds import Thresholds

log = logging.getLogger("edge.policy.runtime")  # never logs secrets, codes or biometric data
TICK_INTERVAL_S = 15  # background maintenance pass (retention purge, step-up expiry, forced-mode expiry)


class BackgroundMixin:
    """tick / heartbeat / loop thread. State is set by PolicyRuntime.__init__."""

    cfg: Thresholds
    bundles: BundleStore
    log: DecisionLog
    monitor: ConnectivityMonitor
    sync: SyncAgent
    sessions: dict[str, StepUpSession]
    fallback_state: Any
    _client: httpx.Client | None
    _lock: threading.RLock
    _real: Callable[[], datetime]
    _rng: Any
    _closed: Any
    _stop: threading.Event
    _thread: threading.Thread | None
    # methods of PolicyRuntime / other mixins (annotations only: never shadow the real methods in the MRO)
    now: Callable[[], datetime]
    _emit: Callable[..., None]
    _expire_forced: Callable[[], None]
    apply_erasures: Callable[[], list[str]]
    _purge_foreign_logs: Callable[[], None]
    _after_sync: Callable[..., None]
    _before_sync: Callable[[], None]

    def tick(self) -> None:
        """One maintenance pass: forced-mode expiry, retention purge, abandoned step-ups, stale pending records,
        consumed-code ids, foreign-kiosk logs. Each stage is isolated (F07): one failure never blocks the others."""
        self._expire_forced()
        for stage in (self.apply_erasures, self._tick_log, self._retire_consumed_codes, self._purge_foreign_logs):
            try:
                stage()
            except Exception as exc:  # noqa: BLE001 - isolated maintenance stage
                log.error("tick stage %s failed (%s)", getattr(stage, "__name__", "?"), type(exc).__name__)

    def _retire_consumed_codes(self) -> None:
        """SC2-D8: persist the signed bundle's consumed_code_ids locally (stays dead even after a bundle reload)."""
        ids = (self.bundles.lvb or {}).get("consumed_code_ids")
        if not isinstance(ids, list):
            return
        now = self._real()
        for cid in ids:
            if isinstance(cid, str) and cid and not self.fallback_state.is_code_consumed(cid):
                self.fallback_state.consume_code(cid, now)

    def _tick_log(self) -> None:
        wall, real = self.now(), self._real()
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
        On success also pulls the deny-only revocation feed (§5.1: every heartbeat), forced OFFLINE included (V2 D)."""
        if self._client is None:
            self.monitor.record(False, "not_configured")
            return False
        try:
            r = self._client.get(str(self.cfg.connectivity.health_path), auth=None)
            ok = r.status_code == 200
            observe = getattr(self._client.auth, "observe", None)  # EO-04: learn the cloud clock before signing
            if callable(observe):
                observe(r)
        except httpx.HTTPError:
            ok = False
        self.monitor.record(ok)
        if ok:  # V2 D: the deny-only feed is pulled even while forced OFFLINE
            try:
                newly = self.sync.pull_revocations()
                for uid in newly:
                    self._emit("REVOCATION_APPLIED", user_id=uid)
            except Exception as exc:  # noqa: BLE001 - F07: a malformed feed body must not stall the loop
                log.warning("revocation feed pull failed (%s)", type(exc).__name__)
        return ok

    def _loop(self) -> None:
        C, S = self.cfg.connectivity, self.cfg.sync
        next_hb = next_tick = next_sync = 0.0
        backoff = float(S.backoff_initial_s)
        refresh_s = float(self.cfg.cache.bundle_refresh_interval_min) * 60
        last_refresh = 0.0
        while not self._stop.is_set():
            t = time.monotonic()
            if t >= next_hb:  # F07: each stage has its own guard and always advances its schedule
                next_hb = t + float(C.heartbeat_interval_s)
                self._guarded(self.heartbeat, "heartbeat")
            if t >= next_tick:
                next_tick = t + TICK_INTERVAL_S
                self._guarded(self.tick, "tick")
            try:
                state = self.monitor.state
                due = state == SYNCING or (state == ONLINE and (self._sendable()  # OS-2: not quarantined rows
                                                                or len(self.sync.erasures) > 0  # R-J replay
                                                                or t - last_refresh > refresh_s))
                if self._client is not None and not self.monitor.forced and due and t >= next_sync:
                    self._before_sync()
                    rep = self.sync.run_once()
                    if rep.get("error") or rep.get("no_progress"):  # OS-3: back off (no connectivity miss)
                        jitter = 1 + float(S.backoff_jitter) * (2 * self._rng.random() - 1)
                        next_sync = t + backoff * jitter
                        backoff = min(backoff * 2, float(S.backoff_max_s))
                    else:
                        backoff, next_sync, last_refresh = float(S.backoff_initial_s), t + 2, t
                        self._after_sync(rep)
            except Exception:  # noqa: BLE001 - the background loop must never die
                next_sync = t + backoff
                backoff = min(backoff * 2, float(S.backoff_max_s))
            self._stop.wait(0.5)

    def _sendable(self) -> bool:
        probe = getattr(self.sync, "has_sendable_work", None)
        return bool(probe()) if callable(probe) else self.log.queue_depth() > 0

    @staticmethod
    def _guarded(fn: Callable[[], Any], what: str) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - the background loop must never die
            log.error("background %s failed (%s)", what, type(exc).__name__)

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
