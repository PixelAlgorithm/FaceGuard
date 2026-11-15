"""POST /v1/sync - idempotent ingest of the kiosk decision queue (SURPRISE_CHALLENGES §SC2.5/§SC2.6).

At-least-once delivery, exactly-once effect:
  * per item: HMAC-SHA256(kiosk key, canonical item JSON without `hmac`) must verify, else rejected;
  * conditional put on attempt_id (`attribute_not_exists`): same content again -> DUPLICATE (not an
    error, safe to purge); same attempt_id with different content -> CONFLICT (variant stored too,
    ALERT_SYNC_CONFLICT) and listed under `duplicates` so the kiosk can purge it;
  * the server never re-decides. It annotates: every OFFLINE ALLOW is re-evaluated with the SAME
    `evaluate_schedule()` the kiosk runs (edge/policy/schedule.py) on the authoritative document at the
    (skew-corrected) decision time -> flags POST_HOC_REVOKED / SCHEDULE_CHANGED + SC2.6 alerts.
Tombstones ({record_type: "tombstone", count, first_seq, last_seq, chain_head}) are accepted and raise
ALERT_RECORDS_PURGED_UNSYNCED. Items are size/shape-guarded: no images or embeddings can be stored.

Hardening (review F9/F15, offline audit F3/F5/M2):
  * decision keys are kiosk-scoped (`<kiosk_id>|<attempt_id>`): another kiosk can never pre-claim an attempt id;
  * the conditional put happens BEFORE re-evaluation, so a lost race / replay never raises alerts twice or claims
    an override code twice; a DUPLICATE answers with the flags of the first delivery (lost-ack resend);
  * one malformed item is rejected on its own (never a 500 that wedges the kiosk's whole queue);
  * a seq gap not covered by a tombstone raises ALERT_CHAIN_GAP, an unhashed record from a chained kiosk raises
    ALERT_LOG_TAMPER (records are still ingested);
  * an offline STAFF_OVERRIDE ALLOW without user_id (A3 manual review) is verdict MANUAL_REVIEW, not a schedule
    mismatch; a code used by a staff_id it was not minted for is a policy violation;
  * a synced STAFF_OVERRIDE ALLOW consumes its code fleet-wide (ScheduleService.consume_code).
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import logging
import re
import uuid
from datetime import datetime, timedelta
from typing import Any

from ..canonical import canonical_json, item_hmac, verify_item_hmac, without
from ..clock import Clock, epoch_s, iso_z, parse_ts
from ..config import Settings
from ..metrics import Metrics
from ..thresholds import CloudThresholds
from .enroll_service import NS_OFFLINE_ENROL
from .kv import KV
from .override_codes import UnknownCode
from .schedule_service import ScheduleService

log = logging.getLogger("hid.cloud.sync")

NS_DEC = "decisions"
NS_TOMB = "tombstones"
NS_ALERTS = "alerts"
NS_CHAIN = "chain"
NS_OVR = "override_use"
NS_TOTP = "totp_use"
NS_SPOOF = "spoof"
NS_BURST = "burst"
NS_KIOSK = "kiosks"
NS_CONSUME_PENDING = "consume_pending"  # key = code_id: a consumption that failed, retried at every ingest (CA-02)
PENDING_TAKEOVER_S = 60  # a PENDING decision claim older than this is re-reconciled by the next delivery (CA-01)
CONSUME_RETRY_BATCH = 20
_CODE_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,64}$")
_STAFF_ID_RE = re.compile(r"^s_[0-9a-z_]{2,32}$")
_METHOD_RE = re.compile(r"^[A-Za-z_]{1,32}$")

SEVERITY = {
    "ALERT_REVOKED_USER_ADMITTED": "high",
    "ALERT_SCHEDULE_MISMATCH": "medium",
    "ALERT_OFFLINE_POLICY_VIOLATION": "high",
    "ALERT_OVERRIDE_USED": "info",
    "ALERT_OVERRIDE_REUSE": "high",
    "ALERT_TOTP_REPLAY": "high",
    "ALERT_SPOOF_BURST": "medium",
    "ALERT_TARGETED_SPOOF": "info",
    "ALERT_LOG_TAMPER": "high",
    "ALERT_SYNC_CONFLICT": "high",
    "ALERT_CLOCK_SKEW": "low",
    "ALERT_RECORDS_PURGED_UNSYNCED": "medium",
    "ALERT_REEVALUATION_UNAVAILABLE": "low",
    "ALERT_CHAIN_GAP": "high",
    "ALERT_OFFLINE_TEMPLATE_UNCONFIRMED": "medium",
}
FLAG_FOR_ALERT = {"ALERT_REVOKED_USER_ADMITTED": "POST_HOC_REVOKED", "ALERT_SCHEDULE_MISMATCH": "SCHEDULE_CHANGED",
                  "ALERT_RECORDS_PURGED_UNSYNCED": "RECORDS_PURGED_UNSYNCED",
                  "ALERT_OFFLINE_TEMPLATE_UNCONFIRMED": "OFFLINE_TEMPLATE_UNCONFIRMED"}
OVERRIDE_METHODS = {"STAFF_OVERRIDE", "STAFF_CODE"}
# data errors of one malformed item (store / programming errors still propagate)
ITEM_DATA_ERRORS = (ValueError, TypeError, AttributeError, KeyError, RecursionError, OverflowError)
DECISIONS = {"ALLOW", "STEP_UP", "DENY"}
MODES = {"ONLINE", "OFFLINE"}
_ID_RE = re.compile(r"^[A-Za-z0-9_.:\-]{1,128}$")
MAX_ITEM_BYTES = 8192
MAX_STR = 512
MAX_NUM_LIST = 64


class ItemRejected(Exception):
    def __init__(self, error: str, detail: str = "") -> None:
        super().__init__(detail or error)
        self.error = error
        self.detail = detail


def guard_minimal(obj: Any, depth: int = 0) -> None:
    """Defence in depth for DPDP minimisation: no long strings (base64 images) or long numeric
    arrays (embeddings) may enter the decision ledger."""
    if depth > 6:
        raise ItemRejected("VALIDATION_ERROR", "nesting too deep")
    if isinstance(obj, str):
        if len(obj) > MAX_STR:
            raise ItemRejected("VALIDATION_ERROR", "string field too long (images/embeddings are never synced)")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            guard_minimal(k, depth + 1)
            guard_minimal(v, depth + 1)
    elif isinstance(obj, list):
        if len(obj) > MAX_NUM_LIST and all(isinstance(x, int | float) for x in obj):
            raise ItemRejected("VALIDATION_ERROR", "numeric array too long (embeddings are never synced)")
        for v in obj:
            guard_minimal(v, depth + 1)


def _ident(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    v = raw.get("idempotency_key") or raw.get("attempt_id")
    return v if isinstance(v, str) else None


def decision_key(kiosk_id: str, attempt_id: str) -> str:
    return f"{kiosk_id}|{attempt_id}"


def _ranges_minus(lo: int, hi: int, covered: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sub-ranges of [lo, hi] not covered by any (first, last) interval (interval arithmetic: no huge sets)."""
    out, cur = [], lo
    for a, b in sorted(covered):
        if b < cur:
            continue
        if a > hi:
            break
        if a > cur:
            out.append((cur, min(hi, a - 1)))
        cur = max(cur, b + 1)
        if cur > hi:
            break
    if cur <= hi:
        out.append((cur, hi))
    return out


def is_tombstone(item: dict) -> bool:
    for fld in ("type", "record_type"):
        v = item.get(fld)
        if isinstance(v, str) and v.upper() == "TOMBSTONE":
            return True
    return "first_seq" in item and "last_seq" in item and "attempt_id" not in item


# Fields the sync agent adds around the stored SC2.5 record (edge/offline/sync.py build_items); they are
# not part of the hashed record.
ENVELOPE_FIELDS = ("hmac", "type", "idempotency_key")
_EDGE_RECORD_HASH = None


def _edge_record_hash():
    """edge.offline.store.compute_record_hash (policy-engine) if importable - the exact kiosk formula."""
    global _EDGE_RECORD_HASH
    if _EDGE_RECORD_HASH is None:
        try:
            from edge.offline.store import compute_record_hash

            _EDGE_RECORD_HASH = compute_record_hash
        except Exception:  # vendored copy missing or broken: documented formula below is identical
            _EDGE_RECORD_HASH = False
    return _EDGE_RECORD_HASH or None


def record_hash_candidates(item: dict) -> set[str]:
    """record_hash = sha256(prev_hash_hex_ascii || canonical_json(record minus prev_hash/record_hash))
    (edge/offline/store.py). Computed on the item minus the sync envelope fields; one tolerant variant
    (prev_hash kept in the body) is also accepted."""
    rec = without(item, *ENVELOPE_FIELDS)
    prev = rec.get("prev_hash") or ""
    out = set()
    fn = _edge_record_hash()
    if fn is not None:
        try:
            out.add(fn(prev, rec))
        except Exception:  # noqa: S110 - fall back to the documented formula
            pass
    try:
        p = prev.encode("ascii")
    except UnicodeEncodeError:
        return out
    out.add(hashlib.sha256(p + canonical_json(without(rec, "prev_hash", "record_hash"))).hexdigest())
    out.add(hashlib.sha256(p + canonical_json(without(rec, "record_hash"))).hexdigest())
    return out


class SyncService:
    def __init__(self, kv: KV, settings: Settings, thresholds: CloudThresholds, clock: Clock,
                 schedule: ScheduleService, metrics: Metrics) -> None:
        self.kv = kv
        self.s = settings
        self.t = thresholds
        self.clock = clock
        self.schedule = schedule
        self.metrics = metrics

    # ------------------------------------------------------------------ helpers
    def _key_for(self, kiosk_id: str) -> str | None:
        return self.s.key_for_kiosk(kiosk_id, self.schedule.known_kiosks())

    def _ttl(self, days: int) -> int:
        return epoch_s(self.clock.now()) + days * 86400

    def is_synthetic(self, item: dict, kiosk_id: str) -> bool:
        """Test / smoke traffic: explicit `synthetic: true`, a test attempt-id prefix, or a test kiosk.
        Synthetic records are stored (idempotency still holds) but flagged and kept out of dashboards."""
        if item.get("synthetic") is True or kiosk_id in self.s.synthetic_kiosks:
            return True
        att = str(item.get("attempt_id") or item.get("idempotency_key") or "")
        return any(att.startswith(p) for p in self.s.synthetic_attempt_prefixes)

    def _alert(self, alerts: list[dict], name: str, kiosk_id: str, attempt_id: str | None = None,
               synthetic: bool = False, **detail: Any) -> dict:
        a = {"alert": name, "severity": SEVERITY.get(name, "info"), "kiosk_id": kiosk_id,
             "attempt_id": attempt_id, "detail": detail, "raised_at": iso_z(self.clock.now()),
             "synthetic": synthetic}
        alerts.append(a)
        self.kv.put(NS_ALERTS, f"{iso_z(self.clock.now())}#{uuid.uuid4().hex[:8]}", a,
                    ttl=self._ttl(self.s.alerts_ttl_days))
        self.metrics.count("SyncAlerts", Alert=name, Synthetic=str(synthetic).lower())
        return a

    # ------------------------------------------------------------------ entry point
    def ingest(self, body: dict, auth_kiosk: str, idempotency_key: str | None = None,
               verbose: bool = False) -> dict:
        """Request (lead round 2): {kiosk_id, batch_id, chain_head, chain_head_hmac, items<=50}
        [+ optional kiosk_now_utc for skew alerts]. Response: {accepted, duplicates,
        rejected[{idempotency_key, error}], flags[{attempt_id, type}], server_time}; verbose=True adds
        alerts / acks (with verdicts) / conflicts / per-item error detail."""
        now = self.clock.now()
        kiosk_id = body.get("kiosk_id")
        if not isinstance(kiosk_id, str) or kiosk_id != auth_kiosk:
            raise ItemRejected("FORBIDDEN", "kiosk_id must match X-Kiosk-Id")
        batch_id = body.get("batch_id") or idempotency_key or f"b_{uuid.uuid4().hex[:12]}"
        items = body.get("items", body.get("records"))
        if not isinstance(items, list):
            raise ItemRejected("VALIDATION_ERROR", "items[] required")
        if len(items) > self.s.sync_max_items:
            raise ItemRejected("VALIDATION_ERROR", f"at most {self.s.sync_max_items} items per batch")
        key = self._key_for(kiosk_id)
        if not key:
            raise ItemRejected("FORBIDDEN", "unknown kiosk")
        self.retry_pending_consumptions()  # CA-02: earlier failed code consumptions (any kiosk)

        out: dict[str, Any] = {"batch_id": batch_id, "kiosk_id": kiosk_id, "accepted": [], "duplicates": [],
                               "conflicts": [], "rejected": [], "flags": [], "alerts": [], "acks": []}
        alerts: list[dict] = out["alerts"]

        # clock skew (SC2.6 rule 5): corrected time is used for re-evaluation and code reuse ordering
        skew = timedelta(0)
        kn = body.get("kiosk_now_utc")
        if isinstance(kn, str):
            try:
                diff = now - parse_ts(kn)
                if abs(diff.total_seconds()) > self.t.clock_skew_alert_s:
                    skew = diff
                    self._alert(alerts, "ALERT_CLOCK_SKEW", kiosk_id, skew_s=round(diff.total_seconds()))
            except ValueError:
                pass

        # chain head MAC (SC2.5: "the chain head is HMAC'd with the kiosk key at each sync")
        chain_head, head_mac = body.get("chain_head"), body.get("chain_head_hmac")
        if chain_head is not None or head_mac is not None:
            ok = isinstance(chain_head, str) and isinstance(head_mac, str) and _hmac.compare_digest(
                _hmac.new(key.encode(), chain_head.encode(), hashlib.sha256).hexdigest(), head_mac.lower())
            if not ok:
                self._alert(alerts, "ALERT_LOG_TAMPER", kiosk_id, reason="chain_head_hmac mismatch")

        def _order(it: Any) -> tuple:
            if not isinstance(it, dict):
                return (2, 0, "")
            seq = it.get("seq") if isinstance(it.get("seq"), int) else it.get("first_seq")
            return (0 if isinstance(seq, int) else 1, seq if isinstance(seq, int) else 0,
                    str(it.get("ts_utc") or it.get("decided_at") or ""))

        doc = None
        chain = self.kv.get(NS_CHAIN, kiosk_id)
        prev_link: dict | None = chain
        new_head = chain
        tomb_ranges = self._batch_tombstone_ranges(items)
        for raw in sorted(items, key=_order):
            ident = _ident(raw)
            try:
                if not isinstance(raw, dict):
                    raise ItemRejected("VALIDATION_ERROR", "item must be an object")
                if len(canonical_json(raw)) > MAX_ITEM_BYTES:
                    raise ItemRejected("VALIDATION_ERROR", "item larger than 8 KB")
                if self.s.sync_require_item_hmac and not verify_item_hmac(key, raw):
                    raise ItemRejected("HMAC_INVALID", "item hmac does not verify")
                guard_minimal(without(raw, "hmac"))
                if is_tombstone(raw):
                    ident = self._tombstone(raw, kiosk_id, batch_id, out, alerts)
                    continue
                rec = self._validate(raw, kiosk_id)
                ident = rec["attempt_id"]
                prev_link, new_head = self._check_chain(raw, rec, kiosk_id, prev_link, new_head, tomb_ranges,
                                                        alerts)
                if doc is None:
                    doc = self.schedule.doc()
                self._ingest_record(raw, rec, kiosk_id, batch_id, skew, doc, out, alerts)
            except ITEM_DATA_ERRORS as exc:  # one malformed item never wedges the batch (F9)
                log.info("sync %s: item rejected (%s)", kiosk_id, type(exc).__name__)
                self._reject(out, raw, ident, kiosk_id, ItemRejected("VALIDATION_ERROR", "malformed item"))
            except ItemRejected as rej:
                self._reject(out, raw, ident, kiosk_id, rej)

        if new_head and new_head != chain:
            self.kv.put(NS_CHAIN, kiosk_id, {k: v for k, v in new_head.items() if k != "_rev"})
        self.kv.put(NS_KIOSK, kiosk_id, {"last_sync_at": iso_z(now), "last_batch_id": batch_id,
                                         "reported_chain_head": chain_head if isinstance(chain_head, str) else None})
        out["server_time"] = iso_z(self.clock.now())
        if verbose:
            return out
        return {
            "accepted": out["accepted"],
            "duplicates": out["duplicates"],
            "rejected": [{"idempotency_key": r["idempotency_key"], "error": r["error"]} for r in out["rejected"]],
            "flags": [{"attempt_id": f["attempt_id"], "type": f["type"]} for f in out["flags"]],
            "server_time": out["server_time"],
        }

    def _reject(self, out: dict, raw: Any, ident: Any, kiosk_id: str, rej: ItemRejected) -> None:
        ident = ident if isinstance(ident, str) else None
        out["rejected"].append({"idempotency_key": ident, "error": rej.error, "detail": rej.detail})
        out["acks"].append({"attempt_id": ident, "status": "REJECTED", "verdict": None})
        syn = str(isinstance(raw, dict) and self.is_synthetic(raw, kiosk_id)).lower()
        self.metrics.count("SyncItems", Status="rejected", Synthetic=syn)

    # ------------------------------------------------------------------ hash chain (tamper evidence)
    @staticmethod
    def _batch_tombstone_ranges(items: list) -> list[tuple[int, int]]:
        out = []
        for it in items:
            if isinstance(it, dict) and is_tombstone(it) and isinstance(it.get("first_seq"), int) \
                    and isinstance(it.get("last_seq"), int):
                out.append((int(it["first_seq"]), int(it["last_seq"])))
        return out

    def _stored_tombstone_ranges(self, kiosk_id: str) -> list[tuple[int, int]]:
        out = []
        for _, t in self.kv.list(NS_TOMB, prefix=f"{kiosk_id}|"):
            if isinstance(t.get("first_seq"), int) and isinstance(t.get("last_seq"), int):
                out.append((int(t["first_seq"]), int(t["last_seq"])))
        return out

    def _check_chain(self, raw: dict, rec: dict, kiosk_id: str, prev_link: dict | None, new_head: dict | None,
                     tomb_ranges: list[tuple[int, int]], alerts: list[dict]) -> tuple[dict | None, dict | None]:
        """Records are always ingested; tampering is flagged. Returns the updated (prev_link, new_head)."""
        ident, seq = rec["attempt_id"], rec.get("seq")
        if not (isinstance(rec.get("record_hash"), str) and rec["record_hash"]):
            if prev_link is not None:  # this kiosk has a chain: an unhashed record cannot be placed in it (M2)
                self._alert(alerts, "ALERT_LOG_TAMPER", kiosk_id, ident, reason="record_hash missing", seq=seq)
            return prev_link, new_head
        if rec["record_hash"].lower() not in record_hash_candidates(raw):
            self._alert(alerts, "ALERT_LOG_TAMPER", kiosk_id, ident, reason="record_hash mismatch", seq=seq)
        prev_seq = prev_link.get("seq") if prev_link else None
        if isinstance(seq, int) and isinstance(prev_seq, int):
            if seq == prev_seq + 1 and rec.get("prev_hash") != prev_link.get("record_hash"):
                self._alert(alerts, "ALERT_LOG_TAMPER", kiosk_id, ident, reason="chain break", seq=seq)
            elif seq > prev_seq + 1:  # records missing between the head and this one (offline audit F3)
                covered = tomb_ranges + self._stored_tombstone_ranges(kiosk_id)
                missing = _ranges_minus(prev_seq + 1, seq - 1, covered)
                if missing:
                    self._alert(alerts, "ALERT_CHAIN_GAP", kiosk_id, ident, missing_first_seq=missing[0][0],
                                missing_last_seq=missing[-1][1], missing_ranges=[list(r) for r in missing[:10]],
                                seq=seq)
        if isinstance(seq, int):
            prev_link = {"seq": seq, "record_hash": rec["record_hash"]}
            if new_head is None or seq > int(new_head.get("seq", -1)):
                new_head = dict(prev_link)
        return prev_link, new_head

    # ------------------------------------------------------------------ validation
    def _validate(self, raw: dict, kiosk_id: str) -> dict:
        rec = without(raw, "hmac")
        att = rec.get("attempt_id")
        if not isinstance(att, str) or not _ID_RE.match(att):
            raise ItemRejected("VALIDATION_ERROR", "attempt_id missing/invalid")
        ik = rec.get("idempotency_key")
        if ik is not None and ik != att:
            raise ItemRejected("VALIDATION_ERROR", "idempotency_key must equal attempt_id")
        if rec.get("kiosk_id") != kiosk_id:
            raise ItemRejected("KIOSK_MISMATCH", "item kiosk_id differs from batch kiosk_id")
        if rec.get("decision") not in DECISIONS:
            raise ItemRejected("VALIDATION_ERROR", "decision must be ALLOW|STEP_UP|DENY")
        if rec.get("mode") not in MODES:
            raise ItemRejected("VALIDATION_ERROR", "mode must be ONLINE|OFFLINE")
        ts_raw = rec.get("ts_utc") or rec.get("decided_at")
        if not isinstance(ts_raw, str):
            raise ItemRejected("VALIDATION_ERROR", "ts_utc (or decided_at) required")
        try:
            rec["_ts"] = parse_ts(ts_raw)
        except ValueError as exc:
            raise ItemRejected("VALIDATION_ERROR", "ts_utc must be ISO-8601 with timezone") from exc
        for fld in ("reason_codes", "resolved_codes"):
            v = rec.get(fld, [])
            if not isinstance(v, list) or not all(isinstance(c, str) for c in v):
                raise ItemRejected("VALIDATION_ERROR", f"{fld} must be a list of strings")
        for fld in ("user_id", "candidate_user_id", "zone"):
            v = rec.get(fld)
            if v is not None and (not isinstance(v, str) or not _ID_RE.match(v)):
                raise ItemRejected("VALIDATION_ERROR", f"{fld} invalid")
        if rec.get("fallback") is not None and not isinstance(rec["fallback"], dict):
            raise ItemRejected("VALIDATION_ERROR", "fallback must be an object or null")
        self._validate_fallback(rec.get("fallback") or {})
        if rec.get("scores") is not None and not isinstance(rec["scores"], dict):
            raise ItemRejected("VALIDATION_ERROR", "scores must be an object")
        seq = rec.get("seq")
        if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool) or seq < 0):
            raise ItemRejected("VALIDATION_ERROR", "seq must be a non-negative integer")
        for fld in ("prev_hash", "record_hash"):
            if rec.get(fld) is not None and not isinstance(rec[fld], str):
                raise ItemRejected("VALIDATION_ERROR", f"{fld} must be a string")
        lat = rec.get("latency_ms")
        if lat is not None and not isinstance(lat, dict | int | float):
            raise ItemRejected("VALIDATION_ERROR", "latency_ms must be an object or a number")
        return rec

    @staticmethod
    def _validate_fallback(fb: dict) -> None:
        """CA-04: the ids a STAFF_OVERRIDE record carries feed code consumption + alerts: strict shapes only."""
        for fld, rx in (("code_id", _CODE_ID_RE), ("staff_id", _STAFF_ID_RE), ("method", _METHOD_RE)):
            v = fb.get(fld)
            if v is not None and (not isinstance(v, str) or not rx.fullmatch(v)):
                raise ItemRejected("VALIDATION_ERROR", f"fallback.{fld} invalid")

    # ------------------------------------------------------------------ records
    def _ingest_record(self, raw: dict, rec: dict, kiosk_id: str, batch_id: str, skew: timedelta, doc: dict,
                       out: dict, alerts: list[dict]) -> None:
        att = rec["attempt_id"]
        key = decision_key(kiosk_id, att)
        content = without(raw, "hmac")
        chash = hashlib.sha256(canonical_json(content)).hexdigest()
        synthetic = self.is_synthetic(raw, kiosk_id)
        ttl = self._ttl(self.s.decisions_ttl_days)
        stored = {**content, "_content_hash": chash, "received_at": iso_z(self.clock.now()), "batch_id": batch_id,
                  "source": "sync", "verdict": "PENDING", "flag_types": [], "flags": [], "alert_names": [],
                  "synthetic": synthetic}
        # claim first, re-evaluate second (F15): a replay / concurrent duplicate never re-raises alerts or re-claims
        # an override code, because only the winner of this conditional put reconciles
        if not self.kv.put_if_absent(NS_DEC, key, stored, ttl=ttl):
            existing = self.kv.get(NS_DEC, key)
            if existing is None or not self._take_over_stale_claim(existing, key, chash, ttl):
                self._existing(existing or {"_content_hash": chash}, att, chash, content, kiosk_id, batch_id, out,
                               alerts)
                return
        verdict, flags = self._reconcile_claimed(rec, key, stored, ttl, skew, kiosk_id, doc, alerts, synthetic)
        out["accepted"].append(att)
        out["acks"].append({"attempt_id": att, "status": "ACCEPTED", "verdict": verdict})
        out["flags"].extend(flags)
        syn = str(synthetic).lower()
        self.metrics.count("SyncItems", Status="accepted", Synthetic=syn)
        self.metrics.count("Decisions", Decision=rec["decision"], Mode=rec["mode"], Synthetic=syn)
        lat = rec.get("latency_ms")
        total = lat.get("total") if isinstance(lat, dict) else None
        if isinstance(total, int | float):
            self.metrics.put("DecisionLatencyMs", float(total), Mode=rec["mode"], Synthetic=syn)

    def _reconcile_claimed(self, rec: dict, key: str, stored: dict, ttl: int, skew: timedelta, kiosk_id: str,
                           doc: dict, alerts: list[dict], synthetic: bool) -> tuple[str, list[dict]]:
        """Re-evaluate a record this delivery has claimed and store the verdict. Any failure rolls the claim back
        (CA-01) so the kiosk's resend re-evaluates from scratch instead of being acked DUPLICATE with a PENDING
        verdict (which would silently drop e.g. ALERT_REVOKED_USER_ADMITTED). If even the roll-back fails, the
        stale PENDING claim is taken over by a delivery after PENDING_TAKEOVER_S."""
        att = rec["attempt_id"]
        n_alerts_before = len(alerts)
        try:
            verdict, flags = self._reconcile(rec, rec["_ts"] + skew, kiosk_id, doc, alerts, synthetic=synthetic)
            final = {**stored, "verdict": verdict, "flag_types": [f["type"] for f in flags],
                     "flags": [{"attempt_id": att, "type": f["type"]} for f in flags],
                     "alert_names": [a["alert"] for a in alerts[n_alerts_before:]]}
            self.kv.put(NS_DEC, key, final, ttl=ttl)
        except Exception:
            try:
                self.kv.delete(NS_DEC, key)
            except Exception:  # noqa: BLE001 - the stale-claim takeover recovers it
                log.warning("sync: claim %s not rolled back; it is re-reconciled after %ss", key, PENDING_TAKEOVER_S)
            raise
        return verdict, flags

    def _take_over_stale_claim(self, existing: dict, key: str, chash: str, ttl: int) -> bool:
        """A PENDING claim of the same content whose delivery died mid-reconcile: claim it again by CAS."""
        if existing.get("verdict") != "PENDING" or existing.get("_content_hash") != chash:
            return False
        try:
            age = (self.clock.now() - parse_ts(str(existing.get("received_at")))).total_seconds()
        except ValueError:
            age = PENDING_TAKEOVER_S
        if age < PENDING_TAKEOVER_S:
            return False  # a concurrent delivery is reconciling it right now
        fresh = {**{k: v for k, v in existing.items() if k != "_rev"}, "received_at": iso_z(self.clock.now())}
        return bool(self.kv.cas(NS_DEC, key, fresh, existing["_rev"], ttl=ttl))

    @staticmethod
    def _stored_flags(existing: dict, att: str) -> list[dict]:
        flags = existing.get("flags")
        if isinstance(flags, list) and all(isinstance(f, dict) for f in flags):
            return [dict(f) for f in flags]
        return [{"attempt_id": att, "type": t} for t in existing.get("flag_types") or [] if isinstance(t, str)]

    def _existing(self, existing: dict, att: str, chash: str, content: dict, kiosk_id: str, batch_id: str,
                  out: dict, alerts: list[dict]) -> None:
        syn = str(bool(existing.get("synthetic"))).lower()
        if existing.get("_content_hash") == chash:
            out["duplicates"].append(att)
            out["acks"].append({"attempt_id": att, "status": "DUPLICATE", "verdict": existing.get("verdict")})
            out["flags"].extend(self._stored_flags(existing, att))  # lost-ack resend: same flags as the first time
            self.metrics.count("SyncItems", Status="duplicate", Synthetic=syn)
            return
        variant = {**content, "_content_hash": chash, "received_at": iso_z(self.clock.now()), "batch_id": batch_id,
                   "source": "sync-conflict", "conflicts_with": existing.get("_content_hash")}
        if self.kv.put_if_absent(NS_DEC, f"{decision_key(kiosk_id, att)}#conflict#{chash[:16]}", variant,
                                 ttl=self._ttl(self.s.decisions_ttl_days)):
            self._alert(alerts, "ALERT_SYNC_CONFLICT", kiosk_id, att, stored_hash=existing.get("_content_hash"),
                        new_hash=chash)
        out["duplicates"].append(att)
        out["conflicts"].append(att)
        out["acks"].append({"attempt_id": att, "status": "CONFLICT", "verdict": existing.get("verdict")})
        self.metrics.count("SyncItems", Status="conflict", Synthetic=syn)

    def _reconcile(self, rec: dict, t_dec: datetime, kiosk_id: str, doc: dict,
                   alerts: list[dict], synthetic: bool = False) -> tuple[str, list[dict]]:
        att, decision, mode = rec["attempt_id"], rec["decision"], rec["mode"]
        flags: list[dict] = []
        verdict = "NOT_REQUIRED"
        fb = rec.get("fallback") or {}
        method = str(fb.get("method") or rec.get("fallback_method") or "").upper()
        codes = rec.get("reason_codes") or []

        def _raise(name: str, **detail: Any) -> None:
            a = self._alert(alerts, name, kiosk_id, att, synthetic=synthetic, **detail)
            if name in FLAG_FOR_ALERT:
                flags.append({"attempt_id": att, "type": FLAG_FOR_ALERT[name], "alert": name,
                              "severity": a["severity"], "detail": detail})

        if decision == "ALLOW" and mode == "OFFLINE":
            uid = rec.get("user_id")
            zone = rec.get("zone") or ((doc.get("kiosks") or {}).get(kiosk_id) or {}).get("zone")
            if not uid and method in OVERRIDE_METHODS:
                # DECISION_POLICY §4 A3: a guard vouched for someone with no usable face (user_id null by spec);
                # there is no schedule to re-evaluate - reviewed by a human, not a mismatch (offline audit F5)
                verdict = "MANUAL_REVIEW"
            elif not uid or not zone:
                verdict = "DISCREPANCY"
                _raise("ALERT_SCHEDULE_MISMATCH", reason="offline ALLOW without user_id/zone")
            elif not self.schedule.policy.available:
                verdict = "NOT_EVALUATED"
                self._alert(alerts, "ALERT_REEVALUATION_UNAVAILABLE", kiosk_id, att, synthetic=synthetic)
            else:
                try:
                    result = self.schedule.evaluate(uid, zone, t_dec, doc)
                except Exception as exc:  # unknown zone etc. -> surface, never silently confirm
                    result = None
                    verdict = "DISCREPANCY"
                    _raise("ALERT_SCHEDULE_MISMATCH", reason=f"re-evaluation error: {type(exc).__name__}")
                if result == "REVOKED":
                    verdict = "DISCREPANCY"
                    _raise("ALERT_REVOKED_USER_ADMITTED", user_id=uid, authoritative_result=result,
                           evaluated_at=iso_z(t_dec))
                elif result == "IN_WINDOW" or (result == "GRACE_WINDOW" and (fb or "FALLBACK_OK" in codes)):
                    verdict = "CONFIRMED"
                elif result is not None:
                    verdict = "DISCREPANCY"
                    _raise("ALERT_SCHEDULE_MISMATCH", user_id=uid, authoritative_result=result,
                           recorded_schedule_version=rec.get("schedule_version") or rec.get("bundle_version"),
                           authoritative_version=doc.get("bundle_version"), evaluated_at=iso_z(t_dec))
                risk = ((doc.get("zones") or {}).get(zone) or {}).get("risk")
                if risk == "high" and "FALLBACK_OK" not in codes and not fb:
                    verdict = "DISCREPANCY"
                    _raise("ALERT_OFFLINE_POLICY_VIOLATION", zone=zone, reason="offline auto-ALLOW in high-risk zone")
                if self._template_unconfirmed(uid):
                    _raise("ALERT_OFFLINE_TEMPLATE_UNCONFIRMED", user_id=uid,
                           reason="offline enrolment never indexed by the cloud")
        elif decision == "ALLOW":
            verdict = "CONFIRMED"

        if decision == "ALLOW" and method in OVERRIDE_METHODS:
            code_id = fb.get("code_id")
            _raise("ALERT_OVERRIDE_USED", staff_id=fb.get("staff_id"), code_id=code_id)
            owner = self.schedule.code_owner(code_id, doc) if isinstance(code_id, str) and code_id else None
            if owner is not None and fb.get("staff_id") not in (None, owner):
                verdict = "DISCREPANCY"
                _raise("ALERT_OFFLINE_POLICY_VIOLATION", code_id=code_id, staff_id=fb.get("staff_id"),
                       reason="override code used under another staff_id")
            home = self.schedule.code_kiosk(code_id, doc) if isinstance(code_id, str) and code_id else None
            if home is not None and home != kiosk_id:  # never in this kiosk's bundle: cannot have been honoured
                verdict = "DISCREPANCY"
                _raise("ALERT_OFFLINE_POLICY_VIOLATION", code_id=code_id, owner_kiosk_id=home,
                       reason="override code bound to another kiosk")
            elif isinstance(code_id, str) and code_id and not self._consume(code_id, kiosk_id, att):
                _raise("ALERT_OFFLINE_POLICY_VIOLATION", code_id=code_id, staff_id=fb.get("staff_id"),
                       reason="unknown override code")
                claim = {"attempt_id": att, "kiosk_id": kiosk_id, "ts_utc": iso_z(t_dec)}
                if not self.kv.put_if_absent(NS_OVR, code_id, claim):
                    first = self.kv.get(NS_OVR, code_id) or {}
                    if first.get("attempt_id") != att:
                        later_is_new = iso_z(t_dec) >= str(first.get("ts_utc", ""))
                        verdict = "DISCREPANCY" if later_is_new else verdict
                        _raise("ALERT_OVERRIDE_REUSE", code_id=code_id,
                               reused_by=att if later_is_new else first.get("attempt_id"),
                               first_use=first.get("attempt_id") if later_is_new else att,
                               other_kiosk=first.get("kiosk_id"))
        if decision == "ALLOW" and method == "TOTP" and isinstance(fb.get("totp_step"), int) and rec.get("user_id"):
            k = f"{rec['user_id']}#{fb['totp_step']}"
            if not self.kv.put_if_absent(NS_TOTP, k, {"attempt_id": att, "kiosk_id": kiosk_id},
                                         ttl=self._ttl(1)):
                first = self.kv.get(NS_TOTP, k) or {}
                if first.get("attempt_id") != att:
                    verdict = "DISCREPANCY"
                    _raise("ALERT_TOTP_REPLAY", user_id=rec["user_id"], totp_step=fb["totp_step"],
                           other_kiosk=first.get("kiosk_id"), other_attempt=first.get("attempt_id"))

        if decision == "DENY" and any(c.startswith(("SPOOF_", "INJECTION_")) for c in codes):
            if rec.get("candidate_user_id"):
                self._alert(alerts, "ALERT_TARGETED_SPOOF", kiosk_id, att, synthetic=synthetic,
                            candidate_user_id=rec["candidate_user_id"])
            if mode == "OFFLINE" and not synthetic:  # test traffic never feeds the burst detector
                self._spoof_burst(kiosk_id, att, t_dec, alerts)
        return verdict, flags

    def _consume(self, code_id: str, kiosk_id: str, att: str) -> bool:
        """Remove the code from the master + list it in every signed bundle (SC2 D8). False = a code the cloud never
        minted (nothing published). A failure is persisted in NS_CONSUME_PENDING and retried at the start of every
        later ingest (CA-02); it never fails this record."""
        pending = {"code_id": code_id, "kiosk_id": kiosk_id, "attempt_id": att, "since": iso_z(self.clock.now())}
        try:
            self.kv.put(NS_CONSUME_PENDING, code_id, pending, ttl=self._ttl(self.s.decisions_ttl_days))
            self.schedule.consume_code(code_id, kiosk_id=kiosk_id, attempt_id=att)
        except UnknownCode:
            self._drop_pending(code_id)
            return False
        except Exception:  # noqa: BLE001 - kept in NS_CONSUME_PENDING, retried by retry_pending_consumptions
            log.exception("override code %s not marked consumed yet; retried at the next sync", code_id)
            return True
        self._drop_pending(code_id)
        return True

    def _drop_pending(self, code_id: str) -> None:
        try:
            self.kv.delete(NS_CONSUME_PENDING, code_id)
        except Exception:  # noqa: BLE001 - a leftover entry is retried and then found already consumed
            log.warning("consume_pending %s not cleared", code_id)

    def retry_pending_consumptions(self) -> int:
        """Re-run consumptions that failed earlier (any kiosk). Returns how many completed."""
        done = 0
        try:
            pending = self.kv.list(NS_CONSUME_PENDING)[:CONSUME_RETRY_BATCH]
        except Exception:  # noqa: BLE001 - the store is down: the ingest itself will report it
            return 0
        for code_id, p in pending:
            try:
                self.schedule.consume_code(code_id, kiosk_id=str(p.get("kiosk_id")),
                                           attempt_id=str(p.get("attempt_id")))
            except UnknownCode:
                pass
            except Exception:  # noqa: BLE001 - still failing: next time
                log.warning("pending consumption of %s still failing", code_id)
                continue
            self._drop_pending(code_id)
            done += 1
        return done

    def _template_unconfirmed(self, uid: str) -> bool:
        if self.kv.get(NS_OFFLINE_ENROL, uid) is None:
            return False
        row = self.kv.get("users", uid) or {}
        return not row.get("face_ids")

    def _spoof_burst(self, kiosk_id: str, att: str, t: datetime, alerts: list[dict]) -> None:
        self.kv.put(NS_SPOOF, f"{kiosk_id}|{iso_z(t)}|{att}", {"attempt_id": att}, ttl=self._ttl(1))
        window = timedelta(minutes=self.t.spoof_burst_window_min)
        lo, hi = iso_z(t - window), iso_z(t)
        recent = [k for k, _ in self.kv.list(NS_SPOOF, prefix=f"{kiosk_id}|") if lo <= k.split("|")[1] <= hi]
        if len(recent) >= self.t.spoof_burst_count:
            bucket = int(t.timestamp()) // int(window.total_seconds())
            if self.kv.put_if_absent(NS_BURST, f"{kiosk_id}|{bucket}", {"at": iso_z(t)}, ttl=self._ttl(1)):
                self._alert(alerts, "ALERT_SPOOF_BURST", kiosk_id, att, count=len(recent),
                            window_min=self.t.spoof_burst_window_min)

    # ------------------------------------------------------------------ tombstones
    def _tombstone(self, raw: dict, kiosk_id: str, batch_id: str, out: dict, alerts: list[dict]) -> str:
        if raw.get("kiosk_id") not in (None, kiosk_id):
            raise ItemRejected("KIOSK_MISMATCH", "tombstone kiosk_id differs from batch kiosk_id")
        for fld in ("count", "first_seq", "last_seq"):
            if not isinstance(raw.get(fld), int):
                raise ItemRejected("VALIDATION_ERROR", f"tombstone.{fld} must be an integer")
        ident = raw.get("idempotency_key") or raw.get("attempt_id") or \
            f"TOMBSTONE:{raw['first_seq']}-{raw['last_seq']}"
        content = without(raw, "hmac")
        if self.kv.put_if_absent(NS_TOMB, f"{kiosk_id}|{ident}", {**content, "received_at": iso_z(self.clock.now()),
                                                                  "batch_id": batch_id},
                                 ttl=self._ttl(self.s.decisions_ttl_days)):
            a = self._alert(alerts, "ALERT_RECORDS_PURGED_UNSYNCED", kiosk_id, ident, count=raw["count"],
                            first_seq=raw["first_seq"], last_seq=raw["last_seq"], chain_head=raw.get("chain_head"))
            out["flags"].append({"attempt_id": ident, "type": "RECORDS_PURGED_UNSYNCED",
                                 "alert": a["alert"], "severity": a["severity"], "detail": a["detail"]})
            out["accepted"].append(ident)
            out["acks"].append({"attempt_id": ident, "status": "ACCEPTED", "verdict": None})
        else:  # resend after a lost ack: same flag as the first delivery
            out["duplicates"].append(ident)
            out["acks"].append({"attempt_id": ident, "status": "DUPLICATE", "verdict": None})
            out["flags"].append({"attempt_id": ident, "type": "RECORDS_PURGED_UNSYNCED"})
        return ident


def sign_item(key: str, item: dict) -> dict:
    """Helper for tools/tests: returns item + hmac."""
    body = without(item, "hmac")
    return {**body, "hmac": item_hmac(key, body)}
