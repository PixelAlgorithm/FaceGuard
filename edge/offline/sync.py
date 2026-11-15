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
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from ulid import ULID

from edge.offline.bundle import BundleStore, canonical_json
from edge.offline.connectivity import SYNCING, ConnectivityMonitor
from edge.offline.crypto import DataCipher
from edge.offline.erasures import PendingErasures
from edge.offline.store import DecisionLog, iso_utc


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
        if self.path and self._c and self.path.exists():
            data = json.loads(self._c.decrypt(self.path.read_bytes(), b"revocations"))
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
                elif kind == "USER":
                    if uid not in self.users:
                        newly.append(uid)
                    self.users[uid] = {"user_id": uid, "revoked_at": it.get("revoked_at"),
                                       "reason": reason or "SYNC"}
                elif kind == "CARD":
                    self.cards.add(uid)
                elif kind == "READMIT":
                    self._readmit(uid, it.get("revoked_at"), restore=reason == RESTORE)
            self.seq = max(self.seq, int(payload.get("revocation_seq") or 0))
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = json.dumps({"seq": self.seq, "users": self.users, "cards": sorted(self.cards),
                           "erased": self.erased, "purge": self.purge}).encode()
        # Owner-only (0600) atomic write like bundle/credentials: mkstemp creates the tmp file 0600 (never
        # briefly world-readable, independent of the umask), then os.replace.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".revocations-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(self._c.encrypt(blob, b"revocations"))
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


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
        self.flags: list[dict[str, Any]] = []
        self.last_report: dict[str, Any] | None = None
        self.last_sync_at: datetime | None = None
        self._lock = threading.Lock()

    def run_once(self) -> dict[str, Any]:
        """One sync cycle. Report = API.md 3.11 POST /v1/admin/sync shape (+ ok / error / bundle detail)."""
        with self._lock:
            report: dict[str, Any] = {"accepted": [], "duplicates": [], "rejected": [], "flags": [], "sent": 0,
                                      "revoked_users": [], "bundle": None, "ok": False, "error": None,
                                      "cloud_erasures": None}
            if self.client is None:
                report["error"] = "CLOUD_UNAVAILABLE: cloud not configured (CLOUD_API_URL empty)"
            else:
                try:
                    self.pull_revocations(report)  # apply revocations BEFORE replaying the queue
                    report["cloud_erasures"] = self._replay_erasures()  # before the bundle: it re-signs it
                    self._push(report)
                    self._pull_bundle(report)
                    report["ok"] = not report["rejected"]
                    self.monitor.record(True)
                    self.last_sync_at = self.clock()
                    if self.monitor.state == SYNCING and self.log.queue_depth() == 0 and report["bundle"] in (
                            "installed", "not_modified"):
                        self.monitor.sync_complete()
                except Exception as exc:  # noqa: BLE001 - a sync cycle must never kill its caller (fail-secure)
                    report["error"] = f"CLOUD_UNAVAILABLE: {type(exc).__name__}: {exc}"
                    self.monitor.record(False, "heartbeat_timeout")
            out = {"accepted": len(report["accepted"]), "duplicates": len(report["duplicates"]),
                   "rejected": len(report["rejected"]), "flags": report["flags"], "queue_depth": self.log.queue_depth(),
                   "ok": report["ok"], "error": report["error"], "bundle": report["bundle"], "sent": report["sent"],
                   "revoked_users": report["revoked_users"], "rejected_items": report["rejected"],
                   "cloud_erasures": report["cloud_erasures"] or self.erasure_status()}
            self.last_report = out
            return out

    # ------------------------------------------------------------ steps
    def pull_revocations(self, report: dict[str, Any] | None = None) -> list[str]:
        """GET /v1/revocations?since=<seq>; applied immediately (also called at every heartbeat)."""
        report = report if report is not None else {}
        r = self.client.get("/v1/revocations", params={"since": self.overlay.seq})
        if r.status_code == 404:
            return []  # endpoint not deployed: bundle revocations still apply
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
        """R-J: DELETE /v1/enroll/{user_id} for every queued erasure; 200 / 204 / 404 = done (idempotent: the cloud
        holds nothing more), any other status stays queued for the next sync. A transport error aborts the cycle
        (raised) with the remaining entries still queued."""
        out: dict[str, Any] = {"done": [], "failed": [], "pending": 0}
        for e in self.erasures.items():
            uid = e["user_id"]
            r = self.client.delete(f"/v1/enroll/{uid}")
            if r.status_code in (200, 204, 404):
                self.erasures.remove(uid)
                out["done"].append(uid)
            else:
                out["failed"].append({"user_id": uid, "status": r.status_code})
        out["pending"] = len(self.erasures)
        return out

    def _push(self, report: dict[str, Any]) -> None:
        sent: set[str] = set()
        while True:
            records = [r for r in self.log.unsynced(self.batch_size + len(sent)) if r["attempt_id"] not in sent]
            records = records[: self.batch_size]
            tombs = [t for t in self.log.tombstones() if t["tombstone_id"] not in sent]
            tombs = tombs[: max(0, self.batch_size - len(records))]
            if not records and not tombs:
                return
            items = build_items(records, tombs, self.key)
            head = records[-1]["record_hash"] if records else self.log.chain_head()
            batch_id = f"b_{ULID()}"
            body = {"kiosk_id": self.kiosk_id, "batch_id": batch_id, "chain_head": head,
                    "chain_head_hmac": hmac.new(self.key, head.encode(), hashlib.sha256).hexdigest(),
                    "kiosk_now_utc": iso_utc(self.clock()), "items": items}
            r = self.client.post("/v1/sync", content=canonical_json(body),
                                 headers={"Content-Type": "application/json", "Idempotency-Key": batch_id})
            r.raise_for_status()
            accepted, duplicates, rejected, flags = _parse_sync_response(r.json())
            acked = set(accepted) | set(duplicates)  # purge on ack; rejected stay until the 24 h purge
            self.log.ack(a["attempt_id"] for a in records if a["attempt_id"] in acked)
            if tombs and not any(x.get("idempotency_key") is None for x in rejected):
                self.log.ack_tombstones(t["tombstone_id"] for t in tombs)
            report["sent"] += len(items)
            report["accepted"] += accepted
            report["duplicates"] += duplicates
            report["rejected"] += rejected
            report["flags"] += flags
            self.flags = (self.flags + flags)[-100:]
            sent |= {r["attempt_id"] for r in records} | {t["tombstone_id"] for t in tombs}
            if not acked and not tombs:
                return  # no progress (everything rejected): keep the records queued

    def _pull_bundle(self, report: dict[str, Any]) -> None:
        headers = {}
        if self.bundles.version is not None:
            headers["If-None-Match"] = f'"{self.bundles.version}"'
        r = self.client.get(f"/v1/schedule/{self.kiosk_id}", headers=headers)
        now = self.clock()
        if r.status_code == 304:
            self.bundles.mark_confirmed(now)
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
        prev = self.bundles.version
        ok, reason = self.bundles.install(candidate, now)
        if not ok:
            report["bundle"] = f"rejected: {reason}"  # LVB kept; alert raised by the store
        else:
            report["bundle"] = "not_modified" if candidate.get("bundle_version") == prev else "installed"


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
