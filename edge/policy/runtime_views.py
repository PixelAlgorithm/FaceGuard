"""PolicyRuntime mixin (edge/policy/runtime.py): read-only status views. GET /v1/mode (mode_status: counts only,
offline F6 / EO-13), the authenticated sync diagnostics (sync_detail), the bundle-side access view
(GET /v1/admin/access/users), TOTP enrolment status and the SC2d store view (GET /v1/admin/store)."""

from __future__ import annotations

import os
import threading
from collections import deque
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import TYPE_CHECKING, Any

from edge.offline.connectivity import OFFLINE, ONLINE
from edge.offline.store import RECORD_FIELDS
from edge.policy import runtime_ops as ops
from edge.policy import schedule as sched_mod
from edge.policy.liveness import enforced
from edge.policy.runtime_common import iso as _iso

if TYPE_CHECKING:
    from edge.offline.bundle import BundleStore
    from edge.offline.connectivity import ConnectivityMonitor
    from edge.offline.credentials import CredentialStore
    from edge.offline.store import DecisionLog
    from edge.offline.sync import RevocationOverlay, SyncAgent
    from edge.policy.ratelimit import RateLimiter
    from edge.policy.thresholds import Thresholds

NEVER_STORED = ["images", "face_crops", "depth_maps", "embeddings", "display_names", "totp_values", "raw_card_ids"]


class ViewsMixin:
    """Status / admin read views. State is set by PolicyRuntime.__init__."""

    cfg: Thresholds
    kiosk_id: str
    bundles: BundleStore
    log: DecisionLog
    monitor: ConnectivityMonitor
    credentials: CredentialStore
    overlay: RevocationOverlay
    sync: SyncAgent
    limiter: RateLimiter
    demo_mode: bool
    _lock: threading.RLock
    _mono: Callable[[], float]
    _template_cache: dict[str, Any]
    _forced: ops.ForcedState
    _random_challenge: str
    _cloud_match: deque[tuple[datetime, bool]]
    # methods of PolicyRuntime / other mixins (annotations only: never shadow the real methods in the MRO)
    now: Callable[[], datetime]
    mode: Callable[[], str]
    kiosk_zone: Callable[[], str | None]
    _demo_clock_full: Callable[[], dict[str, Any]]

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
                "rejected": [{"type": a.get("type"), "at": a.get("at")} for a in self.bundles.alerts[-5:]
                             if isinstance(a, Mapping)],  # public view: no paths / free text
            },
            "revocation_seq": self.overlay.seq,
            "template_cache": dict(self._template_cache),
            "sync_queue_depth": self.log.queue_depth(),
            "demo_clock": self._demo_clock_full() if self.demo_mode else None,
            "kiosk_id": self.kiosk_id,
            "zone": self.kiosk_zone(),
            "policy_version": self.cfg.policy_version,
            "rate_limit": {"enabled": self.limiter.enabled, "locked": left is not None, "retry_after_s": left},
            "last_sync": {"at": _iso(self.sync.last_sync_at), "report": ops.public_report(self.sync.last_report)},
            "server_flags_count": len(self.sync.flags),
            "forced_until": _iso(self._forced.until) if self._forced.forced else None,
            "forced_reason": _public_reason(self._forced.reason) if self._forced.forced else None,
            "revocations_state_lost": bool(getattr(self.overlay, "state_lost", False)),
            "random_challenge": self._random_challenge,
            "policy_bars": self._policy_bars(T, eff),
            "cloud_match": self._cloud_match_status(),
        }

    def sync_detail(self) -> dict[str, Any]:
        """Authenticated diagnostics (audit:read): the full last sync report and the server flags (user / attempt
        ids). GET /v1/mode only carries the counts (offline F6 / EO-13)."""
        return {"last_sync": {"at": _iso(self.sync.last_sync_at), "report": self.sync.last_report},
                "server_flags": list(self.sync.flags[-100:]),
                "forced": {"forced": self._forced.forced, "until": _iso(self._forced.until),
                           "reason": self._forced.reason},
                "bundle_alerts": list(self.bundles.alerts[-20:])}

    def _cloud_match_status(self) -> dict[str, Any]:
        """P7 visibility: a Rekognition miss makes that ATTEMPT offline while heartbeats keep the kiosk ONLINE.
        `degraded` = the latest online attempt fell back to an offline decision (kiosk can explain the badge)."""
        cm = list(self._cloud_match)
        misses = [t for t, ok in cm if not ok]
        oks = [t for t, ok in cm if ok]
        return {"enabled": bool(self.cfg.match.rekognition.enabled), "recent": len(cm), "misses": len(misses),
                "last_miss_at": _iso(max(misses)) if misses else None, "last_ok_at": _iso(max(oks)) if oks else None,
                "degraded": bool(cm) and not cm[-1][1]}

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


def _public_reason(reason: str | None) -> str | None:
    """GET /v1/mode is public: the admin's free-text reason stays in sync_detail(); only "DEMO" is echoed."""
    if reason is None:
        return None
    return ops.DEMO_REASON if reason == ops.DEMO_REASON else "operator"
