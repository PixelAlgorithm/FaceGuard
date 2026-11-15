"""PolicyRuntime mixin (edge/policy/runtime.py): local DPDP erasure (EO-05 / EM-01 / EM-02), pending cloud erasures
(R-J; queue_cloud_erasure itself stays on PolicyRuntime), pending offline enrolments (SC2-D4) and the sync /
reconcile hooks. An erasure is complete only when every hook and the TOTP removal succeeded; a failed one is
retried every tick and keeps the user excluded."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx

from edge.policy import runtime_ops as ops
from edge.policy.runtime_common import CloudUnavailableError

if TYPE_CHECKING:
    from edge.offline.bundle import BundleStore
    from edge.offline.connectivity import ConnectivityMonitor
    from edge.offline.credentials import CredentialStore
    from edge.offline.erasures import PendingEnrolments
    from edge.offline.sync import RevocationOverlay, SyncAgent

log = logging.getLogger("edge.policy.runtime")  # never logs secrets, codes or biometric data


class ErasureMixin:
    """Erasure, enrolment-queue and hook methods. State is set by PolicyRuntime.__init__."""

    bundles: BundleStore
    monitor: ConnectivityMonitor
    credentials: CredentialStore
    overlay: RevocationOverlay
    sync: SyncAgent
    enrolments: PendingEnrolments
    _client: httpx.Client | None
    _lock: threading.RLock
    _erase_lock: threading.Lock
    _real: Callable[[], datetime]
    _erase_hooks: list[Callable[[str], Any]]
    _sync_hooks: list[Callable[[], Any]]
    _reconcile_hooks: list[Callable[[datetime], Any]]
    _pre_sync_hooks: list[Callable[[], Any]]
    _erased: set[str]
    _erase_failed: set[str]
    # method of PolicyRuntime (annotation only: never shadows the real method in the MRO)
    _emit: Callable[..., None]

    def add_erase_hook(self, fn: Callable[[str], Any]) -> None:
        """Register a callback run once per user with an ERASED revocation (bundle or feed), e.g. edge-ml's
        template-store delete. Replayed for users already erased before the hook was registered."""
        with self._lock:
            self._erase_hooks.append(fn)
            done = sorted(self._erased)
        for uid in done:
            self._run_erase_hook(fn, uid)

    def _run_erase_hook(self, fn: Callable[[str], Any], uid: str) -> bool:
        """True when the hook completed. A raising hook = NOT erased (EO-05 / EM-02): retried every tick."""
        return ops.run_hooks([fn], uid, what="erase")

    def _erase_one(self, uid: str, hooks: list[Callable[[str], Any]]) -> bool:
        ok = True
        try:
            self.credentials.remove(uid)
        except Exception as exc:  # noqa: BLE001 - isolated per user (F07): never blocks the purge / sync
            ok = False
            log.error("TOTP secret removal failed for a user (%s)", type(exc).__name__)
        for fn in hooks:
            ok = self._run_erase_hook(fn, uid) and ok  # every hook runs, even after a failure
        return ok

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
                # P1: every queued purge entry is one ERASE event and runs (idempotently) even when the user was
                # already erased, so a repeated ERASE / bundle-before-feed ordering is always acknowledged
                todo = sorted((suspended - self._erased) | set(queued) | self._erase_failed)
                hooks = list(self._erase_hooks)
            done: list[str] = []
            for uid in todo:
                if not self._erase_one(uid, hooks):
                    with self._lock:
                        new_failure = uid not in self._erase_failed
                        self._erase_failed.add(uid)
                    if new_failure:
                        self._emit("ALERT_LOCAL_ERASURE_FAILED", user_id=uid)
                    continue  # EO-05: not complete -> no marker, no purge ack, retried next tick
                with self._lock:
                    self._erase_failed.discard(uid)
                    if uid in suspended:
                        self._erased.add(uid)
                self._emit("USER_ERASED_LOCAL", user_id=uid)
                done.append(uid)
            acked = [u for u in queued if u in done]
            if acked:
                self.overlay.purged(acked)
            return done

    def erasures_complete(self) -> bool:
        """No local erasure is pending or failed (gate for the template reconcile hook, EM-01)."""
        return not self._erase_failed and not self.overlay.pending_purge()

    def reinstate_user(self, user_id: str) -> bool:
        """Re-enrolment of a re-admitted user (edge-ml enroll, after the bundle no longer carries the erasure): drop
        only the overlay's erasure state for `user_id` (and a purge that has not run yet) and the once-per-user
        marker. ADMIN / security revocations stay. Returns True if erasure state was removed."""
        with self._erase_lock:
            if user_id in self._erase_failed or user_id in set(self.overlay.pending_purge()):
                with self._lock:
                    hooks = list(self._erase_hooks)
                if not self._erase_one(user_id, hooks):  # EO-05: the old templates must be gone first
                    raise RuntimeError("a pending local erasure of this user could not be completed")
                with self._lock:
                    self._erase_failed.discard(user_id)
            had = self.overlay.reinstate(user_id)
            with self._lock:
                self._erased.discard(user_id)
            if had:
                self._emit("USER_REINSTATED_LOCAL", user_id=user_id)
            return had

    # ------------------------------------------------------------ pending offline enrolments (SC2-D4)
    def queue_pending_enrolment(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Metadata-only audit record of an enrolment the cloud has not seen ({user_id, actor, at, template_count,
        model, kiosk_id}); ValueError for biometric payloads or bad fields. Replayed by edge-app's sync hook."""
        out = self.enrolments.add(record)
        self._emit("ALERT_OFFLINE_ENROLMENT", user_id=out["user_id"], actor=out.get("actor"))
        return out

    def pending_enrolments(self) -> list[dict[str, Any]]:
        return self.enrolments.items()

    def clear_pending_enrolment(self, user_id: str) -> bool:
        return self.enrolments.remove(user_id)

    def add_pre_sync_hook(self, fn: Callable[[], Any]) -> None:
        """Called synchronously on the sync thread right BEFORE each sync cycle (and its decision batch) when the
        cloud is configured and not forced OFFLINE, e.g. replay of offline-enrolment audit records first.
        Exceptions are isolated and logged; a failing hook never blocks the sync."""
        with self._lock:
            self._pre_sync_hooks.append(fn)

    def _before_sync(self) -> None:
        with self._lock:
            hooks = list(self._pre_sync_hooks)
        ops.run_hooks(hooks, what="pre-sync")

    def add_sync_hook(self, fn: Callable[[], Any]) -> None:
        """Called (background thread, isolated) after every successful sync cycle."""
        with self._lock:
            self._sync_hooks.append(fn)

    def add_reconcile_hook(self, fn: Callable[[datetime], Any]) -> None:
        """EM-01: fn(real UTC now) after an ONLINE cloud pull installed / confirmed the bundle AND every local erasure
        completed (never for an offline reload of the cached bundle)."""
        with self._lock:
            self._reconcile_hooks.append(fn)

    def _after_sync(self, report: Mapping[str, Any]) -> None:
        if report.get("error"):
            return
        with self._lock:
            sync_hooks, rec_hooks = list(self._sync_hooks), list(self._reconcile_hooks)
        ops.run_hooks(sync_hooks, what="sync")
        if report.get("bundle") in ("installed", "not_modified") and self.erasures_complete():
            ops.run_hooks(rec_hooks, self._real(), what="reconcile")

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
