"""Sync agent (SC2.6): revocations first, then pending cloud erasures (R-J), then idempotent queue replay, then
bundle refresh.

POST {CLOUD_API_URL}/v1/sync  (docs/API.md v1.1 §4.4 = lead R13), signed per docs/API.md §0:
  {"kiosk_id", "batch_id": "b_<ULID>", "chain_head", "chain_head_hmac", "kiosk_now_utc", "items": [<= 50]}
  SyncItem      = the SC2.5 record exactly + {"idempotency_key": attempt_id, "hmac"}       (extra="forbid")
  TombstoneItem = {"type": "TOMBSTONE", "count", "first_seq", "last_seq", "chain_head", "hmac"}
  hmac = hex HMAC-SHA256(KIOSK_HMAC_KEY, canonical_json(item without "hmac"))
  chain_head = record_hash of the last record in the batch; chain_head_hmac = HMAC(KIOSK_HMAC_KEY, chain_head)
Response {"accepted": [...], "duplicates": [...], "rejected": [{idempotency_key, error}], "flags": [...]};
accepted + duplicates are purged locally (replay-safe); rejected stay queued; flags (server-side
discrepancies, e.g. POST_HOC_REVOKED) are surfaced in the report and kept for the dashboard.
Conflicts (same attempt_id, different content; API.md 4.4) are acknowledged in `duplicates`: the server keeps
both versions and raises ALERT_SYNC_CONFLICT, so the edge purges its copy. The verbose `acks` shape carries
status CONFLICT, which the edge also surfaces as an ALERT_SYNC_CONFLICT flag.

Bundle freshness (EO-01, RBAC v2 E): the edge stores the full ETag the cloud returned for the installed
bundle and sends it verbatim in If-None-Match (new cloud form "v<version>-<issued_at epoch>", old form
"<version>"; both handled). Without a stored ETag for the current LVB, the derived new form is sent. When
the LVB's effective expiry is within the refresh lead time, the request carries no If-None-Match, so a
re-stamped copy at the same version is always fetched and installed.

SYNCING -> ONLINE (EO-03): every record that can be sent was acked or rejected by the server in this cycle,
every tombstone was acked, the bundle was installed or confirmed, and the revocation feed is not in a lost
state. Rejected and undecryptable rows are quarantined: they stay queued (24 h purge -> tombstone), are
retried at most every sync.backoff_max_s, and are reported, but they no longer hold the kiosk in offline
rules. Server-rejected tombstones are quarantined the same way. `has_sendable_work()` says whether a push
would send anything (quarantined rows alone are not work). The bundle refresh runs even when the queue push
fails. A cloud bundle OLDER than the LVB (local operator re-sign) is never installed nor counted as a
confirmation: report bundle "newer_than_cloud" + no_progress (the caller backs off), one
BUNDLE_NEWER_THAN_CLOUD alert per (cloud, LVB) version pair, and later cycles ask with the cloud's ETag (304).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from ulid import ULID

from edge.offline.bundle import BundleStore, canonical_json, content_digest
from edge.offline.connectivity import SYNCING, ConnectivityMonitor
from edge.offline.crypto import DataCipher, read_encrypted, write_private_atomic
from edge.offline.erasures import PendingErasures
from edge.offline.store import DecisionLog, iso_utc

_log = logging.getLogger("edge.offline.sync")


def item_hmac(key: bytes, item: Mapping[str, Any]) -> str:
    return hmac.new(key, canonical_json({k: v for k, v in item.items() if k != "hmac"}), hashlib.sha256).hexdigest()


TOMBSTONE_FIELDS = ("count", "first_seq", "last_seq", "chain_head")


def build_items(records: list[dict[str, Any]], tombstones: list[dict[str, Any]], key: bytes) -> list[dict[str, Any]]:
    """API.md 4.4: SyncItem = the SC2.5 record exactly + idempotency_key + hmac; TombstoneItem =
    {type, count, first_seq, last_seq, chain_head, hmac} (both extra="forbid" on the server)."""
    items = []
    for r in records:
        it = {**r, "idempotency_key": r["attempt_id"]}
        it["hmac"] = item_hmac(key, it)
        items.append(it)
    for t in tombstones:
        it = {"type": "TOMBSTONE", **{k: t[k] for k in TOMBSTONE_FIELDS}}
        it["hmac"] = item_hmac(key, it)
        items.append(it)
    return items


ERASED = "ERASED"
RESTORE = "RESTORE"


def _ts(value: Any) -> datetime | None:
    """Aware datetime from an ISO-8601 string (Z or offset); None when missing / unparsable / naive."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value)  # py3.11 parses a trailing "Z"
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else None


def _seq(item: Mapping[str, Any]) -> int | None:
    try:
        return int(item["seq"])
    except (KeyError, TypeError, ValueError):
        return None


def _not_after(value: Any, event: datetime) -> bool:
    """True iff `value` parses and is <= `event`. Unparsable stamps are never dropped (fail-secure)."""
    ts = _ts(value)
    return ts is not None and ts <= event


class RevocationOverlay:
    """Revocations pulled from the cloud feed between bundles (docs/API.md §4.3 v1.4), encrypted at rest.

    - `users`: deny entries (USER items: ADMIN, LOST_CARD, ...) -> SCHEDULE_REVOKED online and offline.
    - `cards`: revoked card-ID hashes (CARD items).
    - `erased`: {user_id: ERASE event time}: DPDP erasure state (ERASE items, and legacy USER items with reason
      ERASED). Not a permanent deny entry: a time-aware ERASED suspension (like the bundle's ERASED revocation)
      until a READMIT or the re-enrolment lifts it; enrolment sees reason ERASED (not blocking, edge/enroll.py).
    - `purge`: durable work list of users whose local templates + TOTP must be deleted (one entry per ERASE event),
      consumed by PolicyRuntime.apply_erasures (survives a crash between the feed pull and the purge).
    READMIT items: reason RESTORE drops every USER entry (and the erasure) <= the event time; any other reason
    (READMIT, CONSENT_RECORDED, ADMIN_ACCESS) drops only the erasure <= the event time. A missing / unparsable event
    time drops nothing (an edge that cannot tell keeps denying: fail-secure).
    """

    def __init__(self, path: Path | str | None, data_key: str | bytes | None) -> None:
        self.path = Path(path) if path else None
        self._c = DataCipher(data_key, "revocations") if data_key else None
        self._lock = threading.Lock()
        self.seq = 0
        self.users: dict[str, dict[str, Any]] = {}
        self.cards: set[str] = set()
        self.erased: dict[str, str | None] = {}
        self.purge: list[str] = []
        # EO-08: True after an unreadable revocations.enc was quarantined. Feed revocations may be missing, so
        # the state stays "lost" (fail safe: no SYNCING -> ONLINE, see `state_lost`) until a full re-pull from
        # since=0 has been applied; the flag is persisted so a restart cannot clear it.
        self.state_lost = False
        self.quarantined_to: Path | None = None
        if self.path and self._c:
            self._load()

    def _load(self) -> None:
        assert self.path is not None and self._c is not None
        plain, moved = read_encrypted(self.path, self._c, b"revocations")
        if moved is not None:
            self.state_lost, self.quarantined_to = True, moved
            _log.error("revocation overlay state lost (file quarantined as %s): fail safe until a full feed "
                       "re-pull", moved.name)
            self._save()
            return
        if plain is None:
            return
        try:
            data = json.loads(plain)
            if not isinstance(data, dict):
                raise TypeError("not an object")
            self._restore(data)
        except (ValueError, TypeError, AttributeError) as exc:
            self.seq, self.users, self.cards, self.erased, self.purge = 0, {}, set(), {}, []
            self.state_lost = True
            _log.error("revocation overlay state unparsable (%s): fail safe until a full feed re-pull",
                       type(exc).__name__)

    def _restore(self, data: Mapping[str, Any]) -> None:
        self.state_lost = bool(data.get("state_lost"))
        self.seq, self.cards = int(data.get("seq") or 0), set(data.get("cards") or [])
        self.erased = dict(data.get("erased") or {})
        self.purge = [str(u) for u in data.get("purge") or []]
        for uid, entry in dict(data.get("users") or {}).items():
            if isinstance(entry, Mapping) and entry.get("reason") == ERASED:
                # pre-v1.4 file: an ERASED item was stored as a permanent deny entry -> erasure state
                self._mark_erased(uid, entry.get("revoked_at"))
            else:
                self.users[uid] = entry

    # ------------------------------------------------------------ feed
    def _mark_erased(self, uid: str, at: Any) -> None:
        cur = _ts(self.erased.get(uid))
        new = _ts(at)
        if uid not in self.erased or new is None or (cur is not None and new > cur):
            self.erased[uid] = at if isinstance(at, str) else None

    def apply(self, payload: Mapping[str, Any]) -> list[str]:
        """Apply feed items in order; returns the users newly revoked (USER deny entries) by this payload."""
        newly: list[str] = []
        with self._lock:
            seen = self.seq  # feed position before this payload: a re-sent ERASE must not purge a re-enrolment
            added: list[str] = []  # purge entries queued by this payload
            for it in payload.get("items") or []:
                if not isinstance(it, Mapping):
                    continue
                kind, uid, reason = it.get("type"), it.get("target_id"), it.get("reason")
                if not (isinstance(uid, str) and uid):
                    continue
                if kind == "ERASE" or (kind == "USER" and reason == ERASED):
                    if _seq(it) is not None and _seq(it) <= seen:
                        continue  # already applied (feeds are re-sendable: idempotent)
                    self._mark_erased(uid, it.get("revoked_at"))
                    if uid not in self.purge:
                        self.purge.append(uid)
                        added.append(uid)
                elif kind == "USER":
                    if uid not in self.users:
                        newly.append(uid)
                    self.users[uid] = {"user_id": uid, "revoked_at": it.get("revoked_at"),
                                       "reason": reason or "SYNC"}
                elif kind == "CARD":
                    self.cards.add(uid)
                elif kind == "READMIT":
                    self._readmit(uid, it.get("revoked_at"), restore=reason == RESTORE)
            # EO-M1 / cloud F1: the cursor follows the items actually received, never the server counter (an
            # allocated but not yet written item below the counter would otherwise be skipped forever)
            received = [q for q in (_seq(it) for it in payload.get("items") or [] if isinstance(it, Mapping))
                        if q is not None]
            self.seq = max([self.seq, *received])
            if self.state_lost and seen == 0 and added:
                # OS-1: rebuilding a quarantined overlay replays history. A user readmitted later in it may have
                # re-enrolled here since, so only users still erased at the end of the history are purged. A
                # normal pull (fresh kiosk or incremental) keeps the ERASE+READMIT purge: the pre-erasure local
                # data may still be here then (test_feed_erasures). A deleted (not quarantined) file cannot be
                # told apart from a fresh kiosk: it purges, which is fail-secure (the user re-enrols).
                self.purge = [u for u in self.purge if u not in added or u in self.erased]
            if self.state_lost and seen == 0:
                self.state_lost = False  # a full feed from since=0 was applied: the lost state is rebuilt
                _log.warning("revocation overlay rebuilt from a full feed re-pull")
            self._save()
        return newly

    def _readmit(self, uid: str, at: Any, *, restore: bool) -> None:
        event = _ts(at)
        if event is None:
            return
        if uid in self.erased and _not_after(self.erased[uid], event):
            del self.erased[uid]
        entry = self.users.get(uid)
        if restore and entry is not None and _not_after(entry.get("revoked_at"), event):
            del self.users[uid]

    def reinstate(self, user_id: str) -> bool:
        """Re-enrolment of a re-admitted user (edge-ml enroll): drop only the erasure state (and a purge that has
        not run yet: the fresh, consented templates must survive). ADMIN / security entries stay."""
        with self._lock:
            had = user_id in self.erased or user_id in self.purge
            self.erased.pop(user_id, None)
            self.purge = [u for u in self.purge if u != user_id]
            if had:
                self._save()
            return had

    def pending_purge(self) -> list[str]:
        with self._lock:
            return list(self.purge)

    def purged(self, user_ids: list[str]) -> None:
        with self._lock:
            done = set(user_ids)
            if done & set(self.purge):
                self.purge = [u for u in self.purge if u not in done]
                self._save()

    def erased_users(self) -> set[str]:
        with self._lock:
            return set(self.erased)

    # ------------------------------------------------------------ queries
    def entries(self) -> tuple[dict[str, Any], ...]:
        """Revocations merged into the schedule context: the deny entries, plus a time-aware ERASED suspension per
        erasure not yet lifted (fail-secure between the ERASE event and the re-signed bundle, e.g. if a template
        purge hook failed). The suspension ends with a READMIT or the re-enrolment (reinstate), never permanent."""
        with self._lock:
            erased = tuple({"user_id": u, "revoked_at": at, "reason": ERASED}
                           for u, at in sorted(self.erased.items()) if u not in self.users)
            return tuple(self.users.values()) + erased

    def card_revoked(self, card_id_hash: str) -> bool:
        with self._lock:
            return card_id_hash in self.cards

    def reason(self, user_id: str) -> str | None:
        """Reason of the user's deny entry; else "ERASED" while an erasure is not lifted; else None."""
        with self._lock:
            u = self.users.get(user_id)
            if u is not None:
                return u.get("reason")
            return ERASED if user_id in self.erased else None

    def _save(self) -> None:
        if not (self.path and self._c):
            return
        blob = json.dumps({"seq": self.seq, "users": self.users, "cards": sorted(self.cards),
                           "erased": self.erased, "purge": self.purge, "state_lost": self.state_lost}).encode()
        # Owner-only (0600), fsync, atomic replace (EO-08: never a 0-byte file after a power loss)
        write_private_atomic(self.path, self._c.encrypt(blob, b"revocations"), prefix=".revocations-")


REFRESH_LEAD_STALENESS_FRACTION = 0.5  # fetch unconditionally once the LVB is within staleness/2 of expiry ...
REFRESH_LEAD_MIN_INTERVALS = 2  # ... or within 2 refresh intervals, whichever is longer (cloud: ttl/2)


def derived_etag(bundle: Mapping[str, Any] | None) -> str | None:
    """The cloud's ETag form for a bundle: '"v<bundle_version>-<issued_at epoch>"' (RBAC v2 E)."""
    if not bundle:
        return None
    v, raw = bundle.get("bundle_version"), bundle.get("issued_at")
    if not isinstance(v, int) or isinstance(v, bool) or not isinstance(raw, str):
        return None
    issued = _ts(raw)
    return None if issued is None else f'"v{v}-{int(issued.timestamp())}"'


def _version_of(bundle: Mapping[str, Any]) -> int:
    v = bundle.get("bundle_version")
    return v if isinstance(v, int) and not isinstance(v, bool) else -1


def _bundle_key(bundle: Mapping[str, Any] | None) -> tuple[Any, Any] | None:
    return None if not bundle else (bundle.get("bundle_version"), bundle.get("issued_at"))


class SyncAgent:
    def __init__(self, cfg: Any, log: DecisionLog, bundles: BundleStore, monitor: ConnectivityMonitor, *,
                 client: httpx.Client | None, kiosk_id: str, kiosk_key: bytes | None, overlay: RevocationOverlay,
                 clock: Callable[[], datetime], on_revoked: Callable[[list[str]], None] | None = None,
                 erasures: PendingErasures | None = None, on_feed: Callable[[], Any] | None = None) -> None:
        self.cfg = cfg
        self.log, self.bundles, self.monitor = log, bundles, monitor
        self.client = client
        self.kiosk_id = kiosk_id
        self.key = kiosk_key or b""
        self.overlay = overlay
        self.clock = clock
        self.on_revoked = on_revoked
        self.erasures = erasures if erasures is not None else PendingErasures(None, None)
        self.on_feed = on_feed  # runs right after every applied feed pull (runtime: local DPDP purge)
        self.batch_size = min(int(cfg.sync.batch_size), 50)
        self.quarantine_retry_s = float(cfg.sync.backoff_max_s)  # a server-rejected record is re-sent at most this often
        self.flags: list[dict[str, Any]] = []
        self.last_report: dict[str, Any] | None = None
        self.last_sync_at: datetime | None = None
        self._lock = threading.Lock()
        self._etag: tuple[tuple[Any, Any], str] | None = None  # (LVB (version, issued_at), ETag received)
        self._rejected_at: dict[str, float] = {}  # attempt_id -> monotonic time of the last server rejection
        self._tomb_rejected_at: dict[str, float] = {}  # tombstone_id -> monotonic time of the last rejection
        self._push_complete = False  # last push sent every sendable record and every tombstone was acked
        self._quarantined_last = 0  # queue rows (records + tombstones) held back at the end of the last push
        self._cloud_older: tuple[tuple[Any, int], str | None] | None = None  # ((cloud ver, LVB ver), cloud ETag)

    def run_once(self) -> dict[str, Any]:
        """One sync cycle. Report = API.md 3.11 POST /v1/admin/sync shape (+ ok / error / bundle detail)."""
        with self._lock:
            report: dict[str, Any] = {"accepted": [], "duplicates": [], "rejected": [], "flags": [], "sent": 0,
                                      "revoked_users": [], "bundle": None, "ok": False, "error": None,
                                      "cloud_erasures": None, "no_progress": False, "revocations_feed": None,
                                      "quarantined": {"rejected": 0, "undecryptable": 0, "tombstones": 0}}
            if self.client is None:
                report["error"] = "CLOUD_UNAVAILABLE: cloud not configured (CLOUD_API_URL empty)"
            else:
                self._cycle(report)
            out = {"accepted": len(report["accepted"]), "duplicates": len(report["duplicates"]),
                   "rejected": len(report["rejected"]), "flags": report["flags"], "queue_depth": self.log.queue_depth(),
                   "ok": report["ok"], "error": report["error"], "bundle": report["bundle"], "sent": report["sent"],
                   "revoked_users": report["revoked_users"], "rejected_items": report["rejected"],
                   "cloud_erasures": report["cloud_erasures"] or self.erasure_status(),
                   "quarantined": report["quarantined"], "clock_drift_s": self.clock_drift_s(),
                   "revocations_state_lost": self.overlay.state_lost, "revocations_feed": report["revocations_feed"],
                   "no_progress": report["no_progress"]}
            self.last_report = out  # full detail: authenticated callers only (runtime.sync_detail)
            return out

    def _cycle(self, report: dict[str, Any]) -> None:
        """Feed -> erasures -> queue push -> bundle. The bundle refresh runs even when the push failed (EO-03 d)."""
        error: Exception | None = None
        try:
            self.pull_revocations(report)  # apply revocations BEFORE replaying the queue
            report["cloud_erasures"] = self._replay_erasures()  # before the bundle: it re-signs it
            self._push(report)
        except Exception as exc:  # noqa: BLE001 - a sync cycle must never kill its caller (fail-secure)
            error = exc
        try:
            self._pull_bundle(report)
        except Exception as exc:  # noqa: BLE001
            error = error or exc
        if error is not None:
            report["error"] = f"CLOUD_UNAVAILABLE: {type(error).__name__}: {error}"
            self.monitor.record(False, "heartbeat_timeout")
            return
        report["ok"] = not report["rejected"]
        self.monitor.record(True)
        self.last_sync_at = self.clock()
        if (self.monitor.state == SYNCING and self._push_complete and not self.overlay.state_lost
                and report["bundle"] in ("installed", "not_modified")):
            self.monitor.sync_complete()

    def clock_drift_s(self) -> float | None:
        """Last measured cloud - kiosk clock difference (X-Server-Time, signing.KioskAuth), None if unknown."""
        auth = getattr(self.client, "auth", None)
        drift = getattr(auth, "last_drift_s", None)
        return round(float(drift), 1) if isinstance(drift, int | float) else None

    # ------------------------------------------------------------ steps
    def pull_revocations(self, report: dict[str, Any] | None = None) -> list[str]:
        """GET /v1/revocations?since=<seq>; applied immediately (also called at every heartbeat)."""
        report = report if report is not None else {}
        r = self.client.get("/v1/revocations", params={"since": self.overlay.seq})
        if r.status_code == 404:
            # endpoint not deployed / misrouted: bundle revocations still apply. A lost overlay stays lost (OS-7):
            # only an applied since=0 feed rebuilds it.
            report["revocations_feed"] = "unavailable"
            return []
        report["revocations_feed"] = "ok"
        r.raise_for_status()
        newly = self.overlay.apply(r.json())
        report["revoked_users"] = newly
        if self.on_feed:
            self.on_feed()  # ERASE events: purge local templates + TOTP now (before anyone can re-enrol)
        if newly and self.on_revoked:
            self.on_revoked(newly)
        return newly

    def erasure_status(self) -> dict[str, Any]:
        return {"done": [], "failed": [], "pending": len(self.erasures)}

    def replay_erasures(self) -> dict[str, Any]:
        """Flush the pending cloud erasures now (sync lock held). Transport errors propagate (httpx.HTTPError)."""
        with self._lock:
            return self._replay_erasures()

    def _replay_erasures(self) -> dict[str, Any]:
        """R-J: DELETE /v1/enroll/{user_id}[?actor=<actor>] for every queued erasure (the query is part of the
        signed PATH). 200 / 204 = done; a 404 is done only when the cloud says NOT_FOUND with a reason (e.g.
        NOT_ENROLLED: nothing held); any other status stays queued for the next sync. A transport error
        aborts the cycle (raised) with the remaining entries still queued."""
        out: dict[str, Any] = {"done": [], "failed": [], "pending": 0}
        for e in self.erasures.items():
            uid = e["user_id"]
            actor = e.get("actor")
            params = {"actor": actor} if isinstance(actor, str) and actor else None
            r = self.client.delete(f"/v1/enroll/{uid}", params=params)
            if r.status_code in (200, 204) or (r.status_code == 404 and _is_not_enrolled(r)):
                self.erasures.remove(uid)
                out["done"].append(uid)
            else:
                out["failed"].append({"user_id": uid, "status": r.status_code})
        out["pending"] = len(self.erasures)
        return out

    def has_sendable_work(self) -> bool:
        """OS-2: True when the next push would send something: a new row since the last push, or a quarantined
        record / tombstone whose retry window has elapsed. Quarantined rows alone are not work (no 2 s hot loop
        while ONLINE); runtime uses this instead of queue_depth() > 0."""
        if self.log.queue_depth() > self._quarantined_last:
            return True
        mono = time.monotonic()
        return any(mono - t >= self.quarantine_retry_s
                   for t in (*self._rejected_at.values(), *self._tomb_rejected_at.values()))

    def _held(self, rejected_at: dict[str, float], live: set[str]) -> tuple[dict[str, float], set[str]]:
        mono = time.monotonic()
        kept = {k: t for k, t in rejected_at.items() if k in live}
        return kept, {k for k, t in kept.items() if mono - t < self.quarantine_retry_s}

    def _sendable(self) -> tuple[list[dict[str, Any]], int, int]:
        """(records to send now, quarantined rejected, undecryptable). Reads every unsynced row, so undecryptable
        rows at the head of the queue never starve valid ones (EO-03 b)."""
        depth = self.log.queue_depth()
        rows = self.log.unsynced(max(depth, 1))
        undecryptable = max(0, depth - len(self.log.tombstones()) - len(rows))
        self._rejected_at, held = self._held(self._rejected_at, {r["attempt_id"] for r in rows})
        return [r for r in rows if r["attempt_id"] not in held], len(held), undecryptable

    def _push(self, report: dict[str, Any]) -> None:
        self._push_complete = False
        records, held, undecryptable = self._sendable()
        all_tombs = list(self.log.tombstones())
        self._tomb_rejected_at, held_t = self._held(self._tomb_rejected_at, {t["tombstone_id"] for t in all_tombs})
        tombs = [t for t in all_tombs if t["tombstone_id"] not in held_t]
        rejected_now: set[str] = set()
        rejected_tombs: set[str] = set()
        while records or tombs:
            batch, records = records[: self.batch_size], records[self.batch_size:]
            room = max(0, self.batch_size - len(batch))
            tbatch, tombs = tombs[:room], tombs[room:]
            accepted, duplicates, rejected, flags = self._post_batch(batch, tbatch)
            acked = set(accepted) | set(duplicates)  # purge on ack; rejected are quarantined (24 h purge)
            self.log.ack(a["attempt_id"] for a in batch if a["attempt_id"] in acked)
            if tbatch and any(x.get("idempotency_key") is None for x in rejected):
                rejected_tombs |= {t["tombstone_id"] for t in tbatch}  # OS-6: quarantined like records
            elif tbatch:
                self.log.ack_tombstones(t["tombstone_id"] for t in tbatch)
            report["sent"] += len(batch) + len(tbatch)
            report["accepted"] += accepted
            report["duplicates"] += duplicates
            report["rejected"] += rejected
            report["flags"] += flags
            self.flags = (self.flags + flags)[-100:]
            rejected_now |= {a["attempt_id"] for a in batch if a["attempt_id"] not in acked}
        mono = time.monotonic()
        self._rejected_at.update({a: mono for a in rejected_now})
        self._tomb_rejected_at.update({t: mono for t in rejected_tombs})
        q_rec, q_tomb = held + len(rejected_now), len(held_t) + len(rejected_tombs)
        report["quarantined"] = {"rejected": q_rec, "undecryptable": undecryptable, "tombstones": q_tomb}
        self._quarantined_last = q_rec + undecryptable + q_tomb
        left = {t["tombstone_id"] for t in self.log.tombstones()}
        self._push_complete = left <= (held_t | rejected_tombs)
        if self._quarantined_last:
            _log.warning("sync: %d queue row(s) quarantined (rejected %d, undecryptable %d, tombstones %d)",
                         self._quarantined_last, q_rec, undecryptable, q_tomb)

    def _post_batch(self, records: list[dict[str, Any]], tombs: list[dict[str, Any]]
                    ) -> tuple[list[str], list[str], list[dict], list[dict]]:
        items = build_items(records, tombs, self.key)
        head = records[-1]["record_hash"] if records else self.log.chain_head()
        batch_id = f"b_{ULID()}"
        body = {"kiosk_id": self.kiosk_id, "batch_id": batch_id, "chain_head": head,
                "chain_head_hmac": hmac.new(self.key, head.encode(), hashlib.sha256).hexdigest(),
                "kiosk_now_utc": iso_utc(self.clock()), "items": items}
        r = self.client.post("/v1/sync", content=canonical_json(body),
                             headers={"Content-Type": "application/json", "Idempotency-Key": batch_id})
        r.raise_for_status()
        return _parse_sync_response(r.json())

    # ------------------------------------------------------------ bundle freshness (EO-01)
    def _refresh_lead(self) -> timedelta:
        c = self.cfg.cache
        staleness_h = float(c.bundle_max_staleness_hours)
        interval_min = float(c.bundle_refresh_interval_min)
        return max(timedelta(hours=staleness_h * REFRESH_LEAD_STALENESS_FRACTION),
                   timedelta(minutes=interval_min * REFRESH_LEAD_MIN_INTERVALS))

    def _near_expiry(self, lvb: Mapping[str, Any], now: datetime) -> bool:
        issued, expires = _ts(lvb.get("issued_at")), _ts(lvb.get("expires_at"))
        if issued is None or expires is None:
            return True  # unknown stamps: always fetch the full bundle
        staleness = timedelta(hours=float(self.cfg.cache.bundle_max_staleness_hours))
        effective = min(expires, issued + staleness)
        return effective - now <= self._refresh_lead()

    def if_none_match(self, now: datetime | None = None) -> str | None:
        """The If-None-Match value for the next refresh, or None to fetch unconditionally."""
        lvb = self.bundles.lvb
        if lvb and self._cloud_older is not None and self._cloud_older[0][1] == _version_of(lvb):
            return self._cloud_older[1]  # OS-3: ask "still that older one?" -> 304, no re-download
        if not lvb or self._near_expiry(lvb, now or self.clock()):
            return None
        if self._etag is not None and self._etag[0] == _bundle_key(lvb):
            return self._etag[1]
        return derived_etag(lvb)

    def _pull_bundle(self, report: dict[str, Any], *, force: bool = False) -> None:
        """GET /v1/schedule/{kiosk}. `force` (admin refresh) never sends If-None-Match."""
        now = self.clock()
        inm = None if force else self.if_none_match(now)
        headers = {"If-None-Match": inm} if inm else {}
        r = self.client.get(f"/v1/schedule/{self.kiosk_id}", headers=headers)
        if r.status_code == 304 and self._cloud_older is not None and inm == self._cloud_older[1]:
            report["bundle"], report["no_progress"] = "newer_than_cloud", True  # never a confirmation of the LVB
            return
        if r.status_code == 304:
            self.bundles.mark_confirmed(now)
            self._remember_etag(r, self.bundles.lvb)
            report["bundle"] = "not_modified"
            return
        if r.status_code == 404:
            report["bundle"] = "unavailable"
            return
        r.raise_for_status()
        payload = r.json()
        candidate = payload
        if isinstance(payload, Mapping) and "bundle" in payload and "signature" in payload:
            candidate = {**payload["bundle"], "signature": payload["signature"]}
        before = self.bundles.lvb
        if before is not None and isinstance(candidate, Mapping) and _version_of(candidate) < _version_of(before):
            self._note_cloud_older(r, candidate, before)
            report["bundle"], report["no_progress"] = "newer_than_cloud", True
            return
        self._cloud_older = None
        before_digest = content_digest(before) if before else None
        ok, reason = self.bundles.install(candidate, now)
        if not ok:
            report["bundle"] = f"rejected: {reason}"  # LVB kept; alert raised by the store
            return
        self._remember_etag(r, candidate)
        report["bundle"] = "not_modified" if before_digest == content_digest(candidate) else "installed"

    def _note_cloud_older(self, r: httpx.Response, cloud: Mapping[str, Any], lvb: Mapping[str, Any]) -> None:
        """OS-3 / EO-03 c: the LVB (local operator re-sign) is newer than the cloud's bundle. Not installed, not a
        confirmation, alerted once per (cloud version, LVB version); the operator uploads the LVB with
        PUT /v1/admin/schedule/{kiosk_id}."""
        pair = (cloud.get("bundle_version"), _version_of(lvb))
        if self._cloud_older is None or self._cloud_older[0] != pair:
            self.bundles._alert("BUNDLE_NEWER_THAN_CLOUD", cloud_version=pair[0], installed=pair[1],
                                action="upload the installed bundle: PUT /v1/admin/schedule/{kiosk_id}")
        self._cloud_older = (pair, r.headers.get("ETag"))

    def _remember_etag(self, r: httpx.Response, bundle: Mapping[str, Any] | None) -> None:
        etag = r.headers.get("ETag")
        key = _bundle_key(bundle)
        if etag and key is not None:
            self._etag = (key, etag)


def _is_not_enrolled(r: httpx.Response) -> bool:
    """A cloud 404 meaning "nothing to erase": {"error": {"code": "NOT_FOUND", "reason": <set>}} (EAE-12)."""
    try:
        err = r.json().get("error")
    except (ValueError, AttributeError):
        return False
    return isinstance(err, Mapping) and err.get("code") == "NOT_FOUND" and bool(err.get("reason"))


def _parse_sync_response(resp: Mapping[str, Any]) -> tuple[list[str], list[str], list[dict], list[dict]]:
    """docs/API.md 4.4 shape; tolerant of the SC2.6 {acks, alerts} shape."""
    if "acks" in resp:
        accepted, duplicates, rejected, flags = [], [], [], list(resp.get("alerts") or [])
        for a in resp.get("acks") or []:
            key = a.get("idempotency_key") or a.get("attempt_id")
            status = a.get("status")
            if status == "ACCEPTED":
                accepted.append(key)
            elif status in ("DUPLICATE", "CONFLICT"):
                duplicates.append(key)  # the server holds it (both versions kept on a conflict)
                if status == "CONFLICT":
                    flags.append({"attempt_id": key, "type": "ALERT_SYNC_CONFLICT"})
            else:
                rejected.append({"idempotency_key": key, "error": status})
            if a.get("verdict") == "DISCREPANCY":
                flags.append({"attempt_id": key, "type": "DISCREPANCY"})
        return accepted, duplicates, rejected, flags
    return (list(resp.get("accepted") or []), list(resp.get("duplicates") or []),
            list(resp.get("rejected") or []), list(resp.get("flags") or []))


def utcnow() -> datetime:
    return datetime.now(UTC)
