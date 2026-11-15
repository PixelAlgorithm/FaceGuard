"""Authoritative campus schedule (SC1) + signed per-kiosk offline bundles (SC2.2) + revocation feed.

Master document = config/schedule.example.json format (all kiosks), versioned in the KV store
(ns `schedule`, key `current`, optimistic CAS on `_rev`; history in `schedule_hist`). Every change
(admin edit, revocation, erasure, enrolment fallback update) bumps `bundle_version`.

Per-kiosk bundle (GET /v1/schedule/{kiosk_id}) = master filtered to the kiosk's zone and to users who
could ever be permitted there (role zones, zones_add, visitor-pass zones). Revoked users are KEPT so an
offline kiosk returns SCHEDULE_REVOKED (not just NO_ENTITLEMENT). Signature: HMAC-SHA256 over
canonical JSON of the bundle without `signature` (key SCHEDULE_BUNDLE_HMAC_KEY, value = hex).

Authoritative uploaded bundle (PUT /v1/admin/schedule/{kiosk_id}): an operator-signed bundle
(scripts/sign_bundle.py) is verified (HMAC, kiosk scope, strictly higher bundle_version, not expired, no
publicly documented override codes), becomes the master content at that version, and is served VERBATIM
(its own signature, stamps and override codes) to that kiosk until a later cloud change (revocation,
erasure, admin edit) publishes a higher version or it expires. Override codes: documented demo codes are
stripped on seed, on every publish and before every signature; a stored master that still holds one is
cleaned with a hygiene version bump on read (so kiosks holding the dirty version get a new ETag), and a stored
verbatim upload holding one is never served (code_hygiene.py, same rule as scripts/sign_bundle.py).

Access administration (control panel, PUT /v1/admin/users/{user_id}/access, POST /v1/admin/codes/rotate):
the signed schedule is the single source of a user's role, zones and windows. Every change bumps
bundle_version, is re-signed on the next GET and leaves an audit entry (ns `admin_audit`: who / when / what).

DPDP erasure removes biometric data only: the campus entitlement (users[uid]) stays, suspended by an ERASED
revocation in the bundle (the edge purges templates + TOTP on it) until the user enrols again with consent
or an admin re-admits them with consent: true (R-B, PUT access). The feed gets a non-deny `ERASE` event and,
on re-admission, `READMIT` reason READMIT, never a USER revocation, so the edge's overlay does not turn an
erasure into a permanent ban. Revoke (R-C) = USER revocation (POST /v1/admin/revocations, 409 ALREADY_REVOKED
on a second one); Restore = PUT access with consent + restore (all of the user's revocations dropped, feed
`READMIT` reason RESTORE). User status (list / PUT responses): REVOKED > ERASED > ACTIVE > NOT_IN_SCHEDULE.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import secrets
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from ..canonical import canonical_json, hmac_hex
from ..clock import Clock, epoch_s, iso_z, parse_ts
from ..config import Settings
from ..policy_bridge import PolicyBridge, load_documented_override_values
from ..thresholds import CloudThresholds
from .code_hygiene import documented_code_ids, is_documented, set_edge_min_iterations, strip_documented_codes
from .kv import KV

log = logging.getLogger("hid.cloud.schedule")

NS_SCHED = "schedule"
NS_SCHED_HIST = "schedule_hist"
NS_REV = "revocations"
# feed entries of type READMIT carry exactly one of these reasons (contract enums.readmit_reason)
READMIT_REASONS = ("READMIT", "RESTORE")
NS_COUNTERS = "counters"
NS_KIOSK_BUNDLE = "schedule_kiosk"  # key = kiosk_id: last accepted uploaded bundle (served verbatim)
NS_AUDIT = "admin_audit"  # key = "<ts>#<id>": who changed which access / codes (control panel ledger)
AUDIT_TTL_S = 30 * 86400
DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
_HHMM = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$|^24:00$")
_UPLOAD_DROP_KEYS = ("signature", "issued_at", "expires_at")
CANONICALIZATION = ("json.dumps(bundle_without_signature, sort_keys=True, separators=(',', ':'), "
                    "ensure_ascii=False).encode('utf-8')")


class UnknownKiosk(Exception):
    pass


class ScheduleConflict(Exception):
    pass


class UnknownUser(LookupError):
    pass


class _Unchanged(Exception):  # noqa: N818 - control flow: mutate found nothing to change, do not publish
    pass


def _minutes(t: str) -> int:
    h, m = t.split(":")
    return int(h) * 60 + int(m)


def _check_windows(where: str, windows: Any, zones: dict, *, same_day: bool) -> None:
    """{ZONE: [{days[], start, end}]}: known zones, HH:MM, known days; same_day -> end > start."""
    if not isinstance(windows, dict):
        raise BundleRejected("VALIDATION_ERROR", f"{where}: windows must be an object {{ZONE: [...]}}")
    for z, ws in windows.items():
        if z not in zones:
            raise BundleRejected("VALIDATION_ERROR", f"{where}: unknown zone {z}")
        if not isinstance(ws, list):
            raise BundleRejected("VALIDATION_ERROR", f"{where}.{z}: windows must be a list")
        for w in ws:
            if not isinstance(w, dict) or not _HHMM.match(str(w.get("start", ""))) \
                    or not _HHMM.match(str(w.get("end", ""))):
                raise BundleRejected("VALIDATION_ERROR", f"{where}.{z}: start / end must be HH:MM")
            if w["start"] == "24:00":
                raise BundleRejected("VALIDATION_ERROR", f"{where}.{z}: start must be 00:00-23:59 (only end may "
                                                         f"be 24:00)")
            days = w.get("days")
            if days is not None and (not isinstance(days, list) or any(d not in DAYS for d in days)):
                raise BundleRejected("VALIDATION_ERROR", f"{where}.{z}: days must be a list of {list(DAYS)}")
            if same_day and _minutes(w["end"]) <= _minutes(w["start"]):
                raise BundleRejected("VALIDATION_ERROR", f"{where}.{z}: end {w['end']} must be after start "
                                                         f"{w['start']}")


def _read_windows(windows: Any) -> dict[str, list[dict]]:
    """Admin read view of {ZONE: [window]} (= edge WindowRead): a window without `days` applies every day
    (edge/policy/schedule.py _applies_on), so it is spelled out as all seven days. The stored doc is untouched."""
    out: dict[str, list[dict]] = {}
    for z, ws in (windows or {}).items():
        out[z] = [{**copy.deepcopy(w), "days": list(w["days"]) if w.get("days") is not None else list(DAYS)}
                  for w in ws or []]
    return out


def validate_schedule_doc(doc: Any, *, caller_kiosk: str | None = None) -> None:
    """Structural check of a master document before it becomes authoritative (fail secure: a doc that would
    lock every kiosk out or make filter_for_kiosk raise is refused with VALIDATION_ERROR)."""
    if not isinstance(doc, dict):
        raise BundleRejected("VALIDATION_ERROR", "schedule document must be a JSON object")
    kiosks, zones, roles = doc.get("kiosks"), doc.get("zones"), doc.get("roles")
    if not isinstance(kiosks, dict) or not kiosks:
        raise BundleRejected("VALIDATION_ERROR", "schedule document needs a non-empty kiosks{}")
    if not isinstance(zones, dict) or not zones:
        raise BundleRejected("VALIDATION_ERROR", "schedule document needs a non-empty zones{}")
    if not isinstance(roles, dict) or not roles:
        raise BundleRejected("VALIDATION_ERROR", "schedule document needs a non-empty roles{}")
    if caller_kiosk is not None and caller_kiosk not in kiosks:
        raise BundleRejected("VALIDATION_ERROR", f"the calling kiosk {caller_kiosk} is missing from kiosks{{}} "
                                                 "(it would lock itself out)")
    for kid, k in kiosks.items():
        if not isinstance(k, dict) or k.get("zone") not in zones:
            raise BundleRejected("VALIDATION_ERROR", f"kiosk {kid}: zone must be one of zones{{}}")
    for name, r in roles.items():
        if not isinstance(r, dict):
            raise BundleRejected("VALIDATION_ERROR", f"role {name} must be an object")
        bad = [z for z in r.get("zones") or [] if z not in zones]
        if bad:
            raise BundleRejected("VALIDATION_ERROR", f"role {name}: unknown zones {bad}")
        _check_windows(f"roles.{name}.windows", r.get("windows") or {}, zones, same_day=False)
    users = doc.get("users")
    if users is not None and not isinstance(users, dict):
        raise BundleRejected("VALIDATION_ERROR", "users must be an object {user_id: {...}}")
    for uid, u in (users or {}).items():
        if not isinstance(u, dict):
            raise BundleRejected("VALIDATION_ERROR", f"user {uid} must be an object")
        if u.get("role") not in roles:
            raise BundleRejected("VALIDATION_ERROR", f"user {uid}: role {u.get('role')!r} is not in roles{{}}")
        for key in ("zones_add", "zones_remove"):
            bad = [z for z in u.get(key) or [] if z not in zones]
            if bad:
                raise BundleRejected("VALIDATION_ERROR", f"user {uid}: {key} has unknown zones {bad}")
        _check_windows(f"users.{uid}.extra_windows", u.get("extra_windows") or {}, zones, same_day=False)


def _erased_suspension(doc: dict, uid: str) -> bool:
    return any(isinstance(r, dict) and r.get("user_id") == uid and r.get("reason") == "ERASED"
               for r in doc.get("revocations") or [])


def _readmit(doc: dict, uid: str) -> bool:
    """Lift an ERASED suspension (consent re-recorded / access re-applied). ADMIN revocations are never lifted."""
    revs = doc.get("revocations") or []
    keep = [r for r in revs if not (isinstance(r, dict) and r.get("user_id") == uid and r.get("reason") == "ERASED")]
    if len(keep) == len(revs):
        return False
    doc["revocations"] = keep
    return True


def _user_revocations(doc: dict, uid: str) -> list[dict]:
    return [r for r in doc.get("revocations") or [] if isinstance(r, dict) and r.get("user_id") == uid]


def user_state(doc: dict, uid: str) -> tuple[str, str | None, str | None]:
    """(status, revoked_at, revoked_reason) of `uid` in a master document (docs/API.md §3.18 AccessUser.status).
    REVOKED (any non-ERASED USER revocation, or users[uid].revoked) wins over ERASED (R16); a user only listed
    in revocations (legacy erase that popped users[uid]) is ERASED / REVOKED, not NOT_IN_SCHEDULE."""
    u = (doc.get("users") or {}).get(uid)
    revs = _user_revocations(doc, uid)
    admin = sorted((r for r in revs if r.get("reason") != "ERASED"), key=lambda r: str(r.get("revoked_at") or ""))
    erased = [r for r in revs if r.get("reason") == "ERASED"]
    if admin or (isinstance(u, dict) and u.get("revoked")):
        last = admin[-1] if admin else {}
        return ("REVOKED", last.get("revoked_at") or (u or {}).get("revoked_at"),
                str(last.get("reason") or "ADMIN"))
    if erased:
        return "ERASED", erased[-1].get("revoked_at"), "ERASED"
    return ("ACTIVE" if isinstance(u, dict) else "NOT_IN_SCHEDULE"), None, None


class BundleRejected(Exception):
    """Request refused by the schedule service; `code` is an API error code (docs/API.md §0), `reason` the
    optional machine-readable sub-code (§3.18.6, e.g. UNKNOWN_ROLE, ERASED_IN_BUNDLE)."""

    def __init__(self, code: str, message: str, reason: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.reason = reason


def sign_bundle(bundle: dict, key: str, key_id: str) -> dict:
    """Returns a copy of `bundle` with `signature` = {alg, key_id, value(hex), canonicalization}."""
    body = {k: v for k, v in bundle.items() if k != "signature"}
    out = copy.deepcopy(body)
    out["signature"] = {"alg": "HMAC-SHA256", "key_id": key_id, "value": hmac_hex(key, canonical_json(body)),
                        "canonicalization": CANONICALIZATION}
    return out


def verify_bundle(bundle: dict, key: str) -> bool:
    import hmac as _hmac

    sig = bundle.get("signature") or {}
    if sig.get("alg") != "HMAC-SHA256" or not isinstance(sig.get("value"), str):
        return False
    body = {k: v for k, v in bundle.items() if k != "signature"}
    return _hmac.compare_digest(hmac_hex(key, canonical_json(body)), sig["value"])


def _zone_candidate(doc: dict, uid: str, user: dict, zone: str) -> bool:
    """Static superset: could this user ever be permitted in `zone`? (data minimisation, not policy)."""
    role = (doc.get("roles") or {}).get(user.get("role")) or {}
    if zone in (role.get("zones") or []) or zone in (user.get("zones_add") or []):
        return True
    return any(vp.get("user_id") == uid and zone in (vp.get("zones") or [])
               for vp in doc.get("visitor_passes") or [] if isinstance(vp, dict))


def filter_for_kiosk(doc: dict, kiosk_id: str) -> dict:
    kiosks = doc.get("kiosks") or {}
    if kiosk_id not in kiosks:
        raise UnknownKiosk(kiosk_id)
    zone = kiosks[kiosk_id]["zone"]
    only = [zone]

    def _zones(lst: Any) -> list:
        return [z for z in (lst or []) if z == zone]

    roles = {}
    for name, r in (doc.get("roles") or {}).items():
        rr = {k: v for k, v in r.items() if k not in ("zones", "windows")}
        rr["zones"] = _zones(r.get("zones"))
        rr["windows"] = {z: w for z, w in (r.get("windows") or {}).items() if z == zone}
        roles[name] = rr
    users = {}
    for uid, u in (doc.get("users") or {}).items():
        if not isinstance(u, dict) or not _zone_candidate(doc, uid, u, zone):
            continue
        uu = copy.deepcopy(u)
        uu["zones_add"] = _zones(u.get("zones_add"))
        uu["zones_remove"] = _zones(u.get("zones_remove"))
        uu["extra_windows"] = {z: w for z, w in (u.get("extra_windows") or {}).items() if z == zone}
        uu.pop("note", None)
        users[uid] = uu
    holidays = []
    for h in doc.get("holidays") or []:
        cz = h.get("closed_zones")
        if cz == "ALL" or (isinstance(cz, list) and zone in cz):
            holidays.append({**h, "closed_zones": cz if cz == "ALL" else only})
    exceptions = [{**e, "zones": only} for e in doc.get("exceptions") or [] if zone in (e.get("zones") or [])]
    passes = [{**vp, "zones": only} for vp in doc.get("visitor_passes") or []
              if zone in (vp.get("zones") or []) and vp.get("user_id") in users]
    out = {
        "format_version": doc.get("format_version", 1),
        "bundle_version": doc["bundle_version"],
        "issuer": doc.get("issuer", "hidhack-cloud"),
        "timezone": doc.get("timezone", "Asia/Kolkata"),
        "scope": {"kiosk_ids": [kiosk_id], "note": f"Filtered for {kiosk_id} (zone {zone})."},
        "revocations_version": doc.get("revocations_version", 0),
        "zones": {zone: (doc.get("zones") or {})[zone]},
        "kiosks": {kiosk_id: kiosks[kiosk_id]},
        "roles": roles,
        "exceptions": exceptions,
        "holidays": holidays,
        "visitor_passes": passes,
        "users": users,
        "revocations": [r for r in doc.get("revocations") or [] if r.get("user_id") in users],
        "override_codes": copy.deepcopy(doc.get("override_codes") or {}),
    }
    if "card_id_hash_scheme" in doc:
        out["card_id_hash_scheme"] = doc["card_id_hash_scheme"]
    return out


def _carry_revocations(old: dict, new: dict) -> list[str]:
    """An upload never un-revokes: revocations of the previous master missing from `new` are re-applied."""
    have = {r.get("user_id") for r in new.get("revocations") or [] if isinstance(r, dict)}
    carried = []
    for r in old.get("revocations") or []:
        if not isinstance(r, dict) or r.get("user_id") in have:
            continue
        uid = r.get("user_id")
        new.setdefault("revocations", []).append(copy.deepcopy(r))
        users = new.get("users") or {}
        if r.get("reason") == "ERASED":
            pass  # biometric erasure: the ERASED revocation itself suspends the user until readmitted
        elif isinstance(users.get(uid), dict):
            users[uid]["revoked"] = True
            users[uid]["revoked_at"] = r.get("revoked_at")
        have.add(uid)
        carried.append(str(uid))
    return carried


class ScheduleService:
    def __init__(self, kv: KV, settings: Settings, thresholds: CloudThresholds, clock: Clock,
                 policy: PolicyBridge) -> None:
        self.kv = kv
        self.s = settings
        self.t = thresholds
        self.clock = clock
        self.policy = policy
        self._cache: dict | None = None
        self._cache_at = 0.0
        set_edge_min_iterations(thresholds.override_pbkdf2_iterations)

    # ------------------------------------------------------------------ master document
    def ensure_seeded(self) -> bool:
        if self.kv.get(NS_SCHED, "current") is not None:
            return False
        p = Path(self.s.seed_schedule_path)
        doc = json.loads(p.read_text(encoding="utf-8"))
        doc.pop("signature", None)
        strip_documented_codes(doc)  # e.g. OVR-001..003 of schedule.example.json never reach a bundle
        n_cards = self._recompute_demo_cards(doc)
        version = int(doc.get("bundle_version", 1))
        now = iso_z(self.clock.now())
        rec = {"version": version, "doc": doc, "published_at": now, "reason": f"seed:{p.name}"}
        if not self.kv.put_if_absent(NS_SCHED, "current", rec):
            return False
        self.kv.put(NS_SCHED_HIST, f"{version:08d}", rec, ttl=epoch_s(self.clock.now()) + 7 * 86400)
        base = int(doc.get("revocations_version", 0))
        revs = doc.get("revocations") or []
        self.kv.put_if_absent(NS_COUNTERS, "revocation_seq", {"value": base})
        for i, r in enumerate(revs):
            seq = base - len(revs) + 1 + i
            if seq > 0:
                self.kv.put_if_absent(NS_REV, f"{seq:012d}", {
                    "seq": seq, "type": "USER", "target_id": r.get("user_id"),
                    "revoked_at": r.get("revoked_at"), "reason": r.get("reason", "ADMIN")})
        log.info("schedule seeded from %s (bundle_version %s, %d demo card hashes recomputed)", p.name, version,
                 n_cards)
        self._cache = None
        return True

    def _recompute_demo_cards(self, doc: dict) -> int:
        users = doc.get("users") or {}
        if not any("RECOMPUTED" in str((u.get("fallback") or {}).get("card_id_hash", "")) for u in users.values()):
            return 0
        if not self.s.card_id_pepper:
            log.warning("seed has placeholder card hashes but CARD_ID_PEPPER is unset: card fallback disabled")
            return 0
        from ..policy_bridge import load_card_hash_recompute

        fn = load_card_hash_recompute()
        if fn is None:
            log.warning("scripts/sign_bundle.py unavailable: demo card hashes stay placeholders (fail secure)")
            return 0
        return int(fn(doc, self.s.card_id_pepper.encode("utf-8")))

    def current(self, max_age_s: float = 1.0) -> dict:
        if self._cache is not None and time.monotonic() - self._cache_at < max_age_s:
            return self._cache
        rec = self.kv.get(NS_SCHED, "current")
        if rec is None:
            self.ensure_seeded()
            rec = self.kv.get(NS_SCHED, "current")
        if rec is None:
            raise RuntimeError("no schedule document")
        if documented_code_ids(rec["doc"]):
            # A store seeded before the hygiene rule (live v45) still holds documented codes: publish a cleaned
            # version so kiosks holding the dirty version see a new ETag (stripping only in memory kept the
            # same version, and a kiosk holding it got 304 and kept OVR-001..003).
            try:
                self.publish(lambda _d: None, "hygiene:strip-documented-codes")
                rec = self.kv.get(NS_SCHED, "current") or rec
            except Exception:  # noqa: BLE001 - store hiccup: still never serve the codes
                log.exception("hygiene bump failed; documented codes stripped in memory only")
            strip_documented_codes(rec["doc"])
        self._cache, self._cache_at = rec, time.monotonic()
        return rec

    def doc(self) -> dict:
        return copy.deepcopy(self.current()["doc"])

    def publish(self, mutate: Callable[[dict], Any], reason: str, *, version: int | None = None,
                meta: dict | None = None) -> tuple[int, Any]:
        """Apply `mutate(doc)` with optimistic concurrency; returns (new_version, mutate's return).
        `version` pins the new version (uploaded bundle); it must be greater than the current one."""
        for _ in range(5):
            rec = self.kv.get(NS_SCHED, "current")
            if rec is None:
                self.ensure_seeded()
                continue
            current = int(rec["version"])
            if version is not None and version <= current:
                raise BundleRejected("INVALID_STATE",
                                     f"bundle_version {version} must be greater than the current {current}")
            doc = copy.deepcopy(rec["doc"])
            result = mutate(doc)
            strip_documented_codes(doc)
            new_version = current + 1 if version is None else version
            doc["bundle_version"] = new_version
            new = {"version": new_version, "doc": doc, "published_at": iso_z(self.clock.now()), "reason": reason,
                   **(meta or {})}
            if self.kv.cas(NS_SCHED, "current", new, rec["_rev"]):
                self.kv.put(NS_SCHED_HIST, f"{new_version:08d}", new, ttl=epoch_s(self.clock.now()) + 7 * 86400)
                self._cache = None
                log.info("schedule v%s published (%s)", new_version, reason)
                return new_version, result
        raise ScheduleConflict("concurrent schedule updates; retry")

    def replace(self, new_doc: dict, reason: str = "admin:replace", *, caller_kiosk: str | None = None,
                actor: str | None = None) -> int:
        """PUT /v1/admin/schedule. Validated (validate_schedule_doc) and never un-revokes: revocations of the
        current master missing from `new_doc` (e.g. a doc fetched before a revocation) are carried over."""
        validate_schedule_doc(new_doc, caller_kiosk=caller_kiosk)
        clean = {k: v for k, v in new_doc.items() if k not in _UPLOAD_DROP_KEYS}
        carried: list[str] = []

        def _m(doc: dict) -> None:
            old = copy.deepcopy(doc)
            doc.clear()
            doc.update(copy.deepcopy(clean))
            carried.extend(_carry_revocations(old, doc))
            doc["revocations_version"] = max(int(old.get("revocations_version", 0) or 0),
                                             int(clean.get("revocations_version", 0) or 0))

        version, _ = self.publish(_m, reason)
        self.audit("SCHEDULE_REPLACE", kiosk_id=caller_kiosk, actor=actor, bundle_version=version,
                   revocations_carried_over=carried)
        return version

    # ------------------------------------------------------------------ uploaded (operator-signed) bundles
    def accept_kiosk_bundle(self, kiosk_id: str, bundle: Any) -> dict:
        """PUT /v1/admin/schedule/{kiosk_id}: verify an operator-signed bundle and make it authoritative."""
        if not isinstance(bundle, dict):
            raise BundleRejected("VALIDATION_ERROR", "body must be a signed bundle JSON object")
        sig = bundle.get("signature") if isinstance(bundle.get("signature"), dict) else {}
        if not verify_bundle(bundle, self.s.schedule_bundle_hmac_key):
            raise BundleRejected("FORBIDDEN", "bundle signature does not verify (HMAC-SHA256, schedule bundle key)")
        version = bundle.get("bundle_version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise BundleRejected("VALIDATION_ERROR", "bundle_version must be a positive integer")
        kiosks = bundle.get("kiosks") if isinstance(bundle.get("kiosks"), dict) else {}
        scope = (bundle.get("scope") or {}).get("kiosk_ids") if isinstance(bundle.get("scope"), dict) else None
        if kiosk_id not in kiosks or (scope is not None and kiosk_id not in scope):
            raise BundleRejected("FORBIDDEN", f"bundle scope does not cover kiosk {kiosk_id}")
        master = self.kv.get(NS_SCHED, "current") or self.current()
        if kiosk_id not in (master["doc"].get("kiosks") or {}):
            raise BundleRejected("NOT_FOUND", "unknown kiosk_id in schedule")
        zone = (kiosks.get(kiosk_id) or {}).get("zone")
        if not zone or zone not in (bundle.get("zones") or {}):
            raise BundleRejected("VALIDATION_ERROR", f"bundle has no zone definition for kiosk {kiosk_id}")
        doc_codes = documented_code_ids(bundle)
        if doc_codes:
            raise BundleRejected("VALIDATION_ERROR", f"bundle contains publicly documented override codes "
                                                     f"{doc_codes}; re-sign without --allow-doc-codes")
        now = self.clock.now()
        try:
            expires = parse_ts(str(bundle.get("expires_at", "")))
        except ValueError as exc:
            raise BundleRejected("VALIDATION_ERROR", "bundle expires_at must be ISO-8601 with timezone") from exc
        if expires <= now:
            raise BundleRejected("VALIDATION_ERROR", "bundle already expired; re-sign it")

        value = str(sig.get("value"))
        stored = self.kv.get(NS_KIOSK_BUNDLE, kiosk_id)
        if stored and int(stored["version"]) == version and stored.get("signature") == value:
            return self._upload_result(kiosk_id, stored, unchanged=True)
        resumed = int(master["version"]) == version and master.get("source_signature") == value
        carried: list[str] = []
        mode = "replaced"
        if not resumed:
            floor = max(int(master["version"]), int(stored["version"]) if stored else 0)
            if version <= floor:
                raise BundleRejected("INVALID_STATE", f"bundle_version {version} must be greater than the current "
                                                      f"{floor} (re-sign with scripts/sign_bundle.py --version "
                                                      f"{floor + 1})")
            full = set(master["doc"].get("kiosks") or {}) <= set(kiosks)
            mode = "replaced" if full else "codes_merged"

            def _m(doc: dict) -> None:
                if full:
                    old = copy.deepcopy(doc)
                    doc.clear()
                    doc.update({k: copy.deepcopy(v) for k, v in bundle.items() if k not in _UPLOAD_DROP_KEYS})
                    carried.extend(_carry_revocations(old, doc))
                    doc["revocations_version"] = max(int(old.get("revocations_version", 0)),
                                                     int(doc.get("revocations_version", 0) or 0))
                else:
                    doc["override_codes"] = copy.deepcopy(bundle.get("override_codes") or {"codes": []})

            self.publish(_m, f"upload:{kiosk_id}:{mode}", version=version,
                         meta={"source_signature": value, "source_kiosk": kiosk_id})
        item = {"version": version, "bundle": bundle, "signature": value, "accepted_at": iso_z(now),
                "expires_at": iso_z(expires), "master": mode,
                # a carried-over revocation is missing from the signed content -> serve the cloud re-signed copy
                "verbatim": not carried, "revocations_carried_over": carried}
        self.kv.put(NS_KIOSK_BUNDLE, kiosk_id, item)
        self._cache = None
        log.info("kiosk %s: uploaded bundle v%s accepted (%s, %d override codes, %d revocations carried over)",
                 kiosk_id, version, mode, len((bundle.get("override_codes") or {}).get("codes") or []), len(carried))
        return self._upload_result(kiosk_id, item, unchanged=False)

    @staticmethod
    def _upload_result(kiosk_id: str, item: dict, *, unchanged: bool) -> dict:
        b = item["bundle"]
        return {"kiosk_id": kiosk_id, "bundle_version": int(item["version"]), "etag": f'"{item["version"]}"',
                "unchanged": unchanged, "master": item.get("master"),
                "served": "verbatim" if item.get("verbatim", True) else "cloud_resigned",
                "override_codes": len((b.get("override_codes") or {}).get("codes") or []),
                "revocations_carried_over": list(item.get("revocations_carried_over") or []),
                "expires_at": item.get("expires_at"), "accepted_at": item.get("accepted_at")}

    def _stored_bundle(self, kiosk_id: str, master_version: int) -> dict | None:
        """The uploaded bundle for this kiosk if it is still the current, unexpired content."""
        try:
            item = self.kv.get(NS_KIOSK_BUNDLE, kiosk_id)
        except Exception:  # noqa: BLE001 - store hiccup -> the cloud-signed bundle (same version) is served
            log.warning("uploaded bundle for %s unreadable; serving the cloud-signed bundle", kiosk_id)
            return None
        if not item or not item.get("verbatim", True) or int(item["version"]) < master_version:
            return None
        if documented_code_ids(item.get("bundle") or {}):
            log.warning("uploaded bundle for %s holds documented override codes; serving the cloud-signed bundle",
                        kiosk_id)
            return None
        try:
            if parse_ts(str(item.get("expires_at"))) <= self.clock.now():
                return None
        except ValueError:
            return None
        return item["bundle"]

    def known_kiosks(self) -> set[str]:
        try:
            return set((self.current(max_age_s=5.0)["doc"].get("kiosks") or {}).keys())
        except Exception:
            return set()

    def kiosk_zone(self, kiosk_id: str) -> str | None:
        k = (self.current()["doc"].get("kiosks") or {}).get(kiosk_id)
        return k.get("zone") if isinstance(k, dict) else None

    # ------------------------------------------------------------------ revocations
    def _next_seq(self) -> int:
        for _ in range(10):
            cur = self.kv.get(NS_COUNTERS, "revocation_seq")
            if cur is None:
                if self.kv.put_if_absent(NS_COUNTERS, "revocation_seq", {"value": 1}):
                    return 1
                continue
            nxt = int(cur["value"]) + 1
            if self.kv.cas(NS_COUNTERS, "revocation_seq", {"value": nxt}, cur["_rev"]):
                return nxt
        raise ScheduleConflict("revocation counter contention")

    def revocation_seq(self) -> int:
        cur = self.kv.get(NS_COUNTERS, "revocation_seq")
        return int(cur["value"]) if cur else 0

    def revoke(self, *, rtype: str, target_id: str, reason: str, revoked_at: datetime | None = None,
               force: bool = False, kiosk_id: str | None = None, actor: str | None = None) -> dict:
        if rtype not in {"USER", "CARD"}:
            raise ValueError("type must be USER or CARD")
        if reason == "ERASED":  # only DELETE /v1/enroll creates an erasure (request model refuses it too)
            raise BundleRejected("VALIDATION_ERROR", "ERASED is the DPDP erasure: use DELETE /v1/enroll/{user_id}")
        if rtype == "USER":
            fresh = (self.kv.get(NS_SCHED, "current") or self.current())["doc"]
            if not force and target_id not in (fresh.get("users") or {}) and self.kv.get("users", target_id) is None:
                raise UnknownUser(target_id)
            self._refuse_if_revoked(fresh, target_id)
        ts = iso_z(revoked_at or self.clock.now())
        seq = self._next_seq()
        event = {"seq": seq, "type": rtype, "target_id": target_id, "revoked_at": ts, "reason": reason}

        def _m(doc: dict) -> None:
            if rtype == "USER":
                self._refuse_if_revoked(doc, target_id)  # CAS retry on a doc revoked meanwhile: still no duplicate
                u = (doc.get("users") or {}).get(target_id)
                if isinstance(u, dict):
                    u["revoked"] = True
                    u["revoked_at"] = ts
                doc.setdefault("revocations", []).append({"user_id": target_id, "revoked_at": ts, "reason": reason})
            else:
                for u in (doc.get("users") or {}).values():
                    fb = u.get("fallback") or {}
                    if fb.get("card_id_hash") == target_id:
                        fb["card_id_hash"] = None
            doc["revocations_version"] = max(seq, int(doc.get("revocations_version", 0)))

        # publish first: a failed publish must not leave an orphan feed event (the burnt seq is a harmless gap)
        version, _ = self.publish(_m, f"revoke:{rtype}:{reason}")
        self.kv.put(NS_REV, f"{seq:012d}", event)
        event["bundle_version"] = version
        self.audit("REVOKE", kiosk_id=kiosk_id, actor=actor, user_id=target_id if rtype == "USER" else None,
                   type=rtype, reason=reason, bundle_version=version, seq=seq)
        return event

    @staticmethod
    def _refuse_if_revoked(doc: dict, uid: str) -> None:
        if user_state(doc, uid)[0] == "REVOKED":
            raise BundleRejected("INVALID_STATE", f"user {uid} is already revoked", reason="ALREADY_REVOKED")

    def erase_user(self, user_id: str, *, kiosk_id: str | None = None) -> dict:
        """DPDP erasure of the BIOMETRIC data: the campus entitlement (users[uid]: role, zones, windows) is kept
        but suspended by an ERASED revocation (bundle) until the user enrols again with consent or an admin
        re-applies access. fallback.totp_enrolled is cleared (the edge drops the secret on ERASED). The feed gets
        a non-deny ERASE event (not a USER revocation: the edge overlay is deny-only and permanent)."""
        ts = iso_z(self.clock.now())
        seq = self._next_seq()
        event = {"seq": seq, "type": "ERASE", "target_id": user_id, "revoked_at": ts, "reason": "ERASED"}

        def _m(doc: dict) -> bool:
            u = (doc.get("users") or {}).get(user_id)
            if isinstance(u, dict):
                fb = u.setdefault("fallback", {})
                fb["totp_enrolled"] = False
            doc["revocations"] = [r for r in doc.get("revocations") or []
                                  if not (r.get("user_id") == user_id and r.get("reason") == "ERASED")]
            doc["revocations"].append({"user_id": user_id, "revoked_at": ts, "reason": "ERASED"})
            doc["revocations_version"] = max(seq, int(doc.get("revocations_version", 0)))
            return isinstance(u, dict)

        version, kept = self.publish(_m, "erase")
        self.kv.put(NS_REV, f"{seq:012d}", event)
        self.audit("ERASE", kiosk_id=kiosk_id, user_id=user_id, bundle_version=version, seq=seq)
        event["bundle_version"] = version
        event["schedule_entry_removed"] = False
        event["schedule_entry_kept"] = kept
        return event

    def record_enrolment(self, user_id: str, *, totp_enrolled: bool | None, card_id_hash: str | None,
                         kiosk_id: str | None = None) -> dict:
        """After a successful (consented) cloud enrolment: update the schedule user's fallback flags and lift an
        ERASED suspension. Never creates a schedule user and never changes role / display (the admin access
        endpoint does that). Publishes only when something changes (no version churn on re-enrolment)."""
        doc = self.current()["doc"]
        user = (doc.get("users") or {}).get(user_id)
        fb = (user or {}).get("fallback") or {}
        want_totp = isinstance(user, dict) and totp_enrolled is not None and fb.get("totp_enrolled") != bool(
            totp_enrolled)
        want_card = isinstance(user, dict) and card_id_hash is not None and fb.get("card_id_hash") != card_id_hash
        want_readmit = _erased_suspension(doc, user_id)
        if not (want_totp or want_card or want_readmit):
            return {"bundle_version": int(self.current()["version"]), "in_schedule": isinstance(user, dict),
                    "role": (user or {}).get("role"), "readmitted": False, "changed": False}

        def _m(d: dict) -> dict:
            u = (d.get("users") or {}).get(user_id)
            if isinstance(u, dict):
                f = u.setdefault("fallback", {})
                if totp_enrolled is not None:
                    f["totp_enrolled"] = bool(totp_enrolled)
                if card_id_hash is not None:
                    f["card_id_hash"] = card_id_hash
            return {"readmitted": _readmit(d, user_id), "in_schedule": isinstance(u, dict),
                    "role": (u or {}).get("role")}

        version, out = self.publish(_m, "enroll:fallback")
        if out["readmitted"]:
            self._feed_event("READMIT", user_id, "READMIT")  # §4.3: consented enrolment
            self.audit("READMIT", kiosk_id=kiosk_id, user_id=user_id, bundle_version=version, via="enrolment")
        return {"bundle_version": version, "changed": True, **out}

    def set_user_fallback(self, user_id: str, *, totp_enrolled: bool | None, card_id_hash: str | None) -> int | None:
        """Compatibility wrapper (older callers): the schedule version, or None if the user is not scheduled."""
        out = self.record_enrolment(user_id, totp_enrolled=totp_enrolled, card_id_hash=card_id_hash)
        return out["bundle_version"] if out["in_schedule"] else None

    def _feed_event(self, etype: str, target_id: str, reason: str) -> int:
        if etype == "READMIT" and reason not in READMIT_REASONS:  # contract enums.readmit_reason (docs/API.md §4.3)
            raise ValueError(f"READMIT feed reason must be one of {READMIT_REASONS}, not {reason!r}")
        seq = self._next_seq()
        self.kv.put(NS_REV, f"{seq:012d}", {"seq": seq, "type": etype, "target_id": target_id,
                                            "revoked_at": iso_z(self.clock.now()), "reason": reason})
        return seq

    # ------------------------------------------------------------------ audit ledger (control panel)
    def audit(self, action: str, *, kiosk_id: str | None = None, actor: str | None = None, **detail: Any) -> None:
        """Best effort: an audit write failure never undoes the (already published) change, but is logged."""
        now = self.clock.now()
        item = {"ts_utc": iso_z(now), "action": action, "kiosk_id": kiosk_id, "actor": actor,
                **{k: v for k, v in detail.items() if v is not None}}
        try:
            # key = ts + wall-clock ns tiebreak: entries written within one second keep their order
            self.kv.put(NS_AUDIT, f"{iso_z(now)}#{time.time_ns():020d}#{uuid.uuid4().hex[:8]}", item,
                        ttl=epoch_s(now) + AUDIT_TTL_S)
        except Exception:  # noqa: BLE001
            log.exception("audit entry not written: %s", action)

    def audit_entries(self, limit: int = 100, user_id: str | None = None) -> list[dict]:
        rows = sorted(((k, it) for k, it in self.kv.list(NS_AUDIT) if user_id is None or it.get("user_id") == user_id),
                      key=lambda kv: (str(kv[1].get("ts_utc")), kv[0]))
        items = [it for _, it in rows]
        for it in items:
            it.pop("_rev", None)
        return items[-limit:]

    # ------------------------------------------------------------------ access administration
    def list_users(self) -> dict:
        """GET /v1/admin/users (docs/API.md §4.9a): master users ∪ cloud enrolment store ∪ users only named by a
        revocation (a legacy erase popped users[uid]: shown ERASED so the panel can offer "Re-admit"). No card
        hashes, no secrets, no faces."""
        rec = self.current()
        doc = rec["doc"]
        rows = {k: v for k, v in self.kv.list("users")}
        sched = doc.get("users") or {}
        revoked_ids = {str(r.get("user_id")) for r in doc.get("revocations") or []
                       if isinstance(r, dict) and r.get("user_id")}
        out = []
        for uid in sorted(set(sched) | set(rows) | revoked_ids):
            u = sched.get(uid) if isinstance(sched.get(uid), dict) else None
            row = rows.get(uid) or {}
            status, revoked_at, revoked_reason = user_state(doc, uid)
            out.append({
                "user_id": uid,
                "display": (u or {}).get("display") or row.get("display_name"),
                "role": (u or {}).get("role"),
                "in_schedule": u is not None,
                "status": status,
                "revoked_at": revoked_at,
                "revoked_reason": revoked_reason,
                **self._entry_fields(u),
                "enrolled": bool(row.get("face_ids")),
                "faces": len(row.get("face_ids") or []),
                "consent_version": (row.get("consent") or {}).get("version"),
            })
        roles = {n: {"zones": list(r.get("zones") or []), "windows": _read_windows(r.get("windows"))}
                 for n, r in (doc.get("roles") or {}).items() if isinstance(r, dict)}
        zones = {z: {"risk": (v or {}).get("risk", "high"),
                     "requires_explicit_grant": bool((v or {}).get("requires_explicit_grant"))}
                 for z, v in (doc.get("zones") or {}).items()}
        return {"bundle_version": int(rec["version"]), "published_at": rec.get("published_at"),
                "timezone": doc.get("timezone", "Asia/Kolkata"), "roles": roles, "zones": zones,
                "kiosks": {k: {"zone": v.get("zone"), "label": v.get("label")}
                           for k, v in (doc.get("kiosks") or {}).items() if isinstance(v, dict)},
                "staff_ids": self.staff_ids(doc), "users": out}

    @staticmethod
    def staff_ids(doc: dict) -> list[str]:
        """Staff ids holding override codes (+ an optional master `staff_ids` list). Ids only, never codes."""
        ids = {str(c.get("staff_id")) for c in (doc.get("override_codes") or {}).get("codes") or []
               if isinstance(c, dict) and c.get("staff_id")}
        ids |= {str(x) for x in doc.get("staff_ids") or [] if isinstance(x, str)}
        return sorted(ids)

    @staticmethod
    def _entry_fields(u: dict | None) -> dict:
        fb = (u or {}).get("fallback") or {}
        return {"zones_add": list((u or {}).get("zones_add") or []),
                "zones_remove": list((u or {}).get("zones_remove") or []),
                "extra_windows": _read_windows((u or {}).get("extra_windows")),
                "valid_from": (u or {}).get("valid_from"),
                "valid_until": (u or {}).get("valid_until"),
                "fallback": {"totp_enrolled": bool(fb.get("totp_enrolled")), "card": bool(fb.get("card_id_hash"))}}

    def update_access(self, user_id: str, change: dict[str, Any], *, kiosk_id: str | None = None,
                      actor: str | None = None) -> dict:
        """PUT /v1/admin/users/{user_id}/access (docs/API.md §3.18.2 state rules, §4.9a). `change` holds only the
        fields the caller sent (role always; consent / restore are flags, not stored fields).

        absent  + display + consent:true  -> created          (else 422 CONSENT_REQUIRED / DISPLAY_REQUIRED)
        ACTIVE                            -> updated, or unchanged (same version, no publish)
        ERASED  + consent:true            -> ERASED revocation dropped, readmitted, feed READMIT/READMIT
        ERASED  without consent:true      -> 409 ERASED_IN_BUNDLE
        REVOKED + consent + restore       -> all of the user's revocations dropped, restored, feed READMIT/RESTORE
        REVOKED + consent, no restore     -> 409 USER_REVOKED
        REVOKED without consent           -> edit applied, revocation kept, warning"""
        now = self.clock.now()
        for key in ("valid_from", "valid_until"):
            if change.get(key) is not None:
                try:
                    change[key] = iso_z(parse_ts(str(change[key])))
                except ValueError as exc:
                    raise BundleRejected("VALIDATION_ERROR", f"{key} must be ISO-8601 with timezone") from exc
        consent = change.pop("consent", None) is True
        restore = change.pop("restore", None) is True
        row = self.kv.get("users", user_id) or {}

        def _m(doc: dict) -> dict:
            roles, zones = doc.get("roles") or {}, doc.get("zones") or {}
            if change["role"] not in roles:
                raise BundleRejected("VALIDATION_ERROR", f"role {change['role']!r} is not one of {sorted(roles)}",
                                     reason="UNKNOWN_ROLE")
            bad = sorted({z for z in change.get("zones_add") or [] if z not in zones}
                         | {z for z in (change.get("extra_windows") or {}) if z not in zones})
            if bad:
                raise BundleRejected("VALIDATION_ERROR", f"unknown zones {bad} (known: {sorted(zones)})",
                                     reason="UNKNOWN_ZONE")
            if "extra_windows" in change:
                _check_windows("extra_windows", change["extra_windows"] or {}, zones, same_day=True)
            users = doc.setdefault("users", {})
            old = copy.deepcopy(users.get(user_id)) if isinstance(users.get(user_id), dict) else None
            status, _, _ = user_state(doc, user_id)
            if old is None:
                if not consent:
                    raise BundleRejected("VALIDATION_ERROR", "consent: true is required to add a new user",
                                         reason="CONSENT_REQUIRED")
                if not change.get("display"):
                    raise BundleRejected("VALIDATION_ERROR", "display is required to add a new user",
                                         reason="DISPLAY_REQUIRED")
            if status == "REVOKED" and consent and not restore:
                raise BundleRejected("INVALID_STATE", f"user {user_id} is revoked: use Restore (restore: true) first",
                                     reason="USER_REVOKED")
            if status == "ERASED" and not consent:
                raise BundleRejected("INVALID_STATE", f"user {user_id} was erased (DPDP): re-admit with consent: true",
                                     reason="ERASED_IN_BUNDLE")
            if old is None:
                u = {"display": change["display"], "role": change["role"], "zones_add": [], "zones_remove": [],
                     "extra_windows": {}, "valid_from": None, "valid_until": None, "revoked": False,
                     "revoked_at": None,
                     # a cloud enrolment made before the user was scheduled left its card hash / TOTP flag
                     "fallback": {"totp_enrolled": bool(row.get("totp_enrolled")),
                                  "card_id_hash": row.get("card_id_hash")}}
            else:
                u = copy.deepcopy(old)
            for key in ("display", "role", "zones_add", "extra_windows"):
                if key in change and change[key] is not None:
                    u[key] = copy.deepcopy(change[key])
            for key in ("valid_from", "valid_until"):
                if key in change:  # explicit null clears the bound
                    u[key] = change[key]
            vf, vu = u.get("valid_from"), u.get("valid_until")
            if vf and vu and parse_ts(vu) <= parse_ts(vf):
                raise BundleRejected("VALIDATION_ERROR", "valid_until must be after valid_from")
            readmitted = restored = False
            if status == "REVOKED" and consent and restore:
                revs = doc.get("revocations") or []
                readmitted = any(r.get("reason") == "ERASED" for r in _user_revocations(doc, user_id))
                doc["revocations"] = [r for r in revs if not (isinstance(r, dict) and r.get("user_id") == user_id)]
                u["revoked"], u["revoked_at"] = False, None
                restored = True
            elif status == "ERASED" and consent:
                readmitted = _readmit(doc, user_id)
            diff = {k: [None if old is None else old.get(k), u.get(k)]
                    for k in ("display", "role", "zones_add", "extra_windows", "valid_from", "valid_until")
                    if (u.get(k) not in (None, [], {}) if old is None else old.get(k) != u.get(k))}
            if old is not None and not diff and not readmitted and not restored:
                raise _Unchanged
            users[user_id] = u
            return {"created": old is None, "diff": diff, "readmitted": readmitted, "restored": restored,
                    "previous_status": status, "user": copy.deepcopy(u),
                    "previous_role": None if old is None else old.get("role")}

        try:
            version, out = self.publish(_m, f"admin:access:{user_id}", meta={"actor": actor, "kiosk_id": kiosk_id})
        except _Unchanged:
            rec = self.current()
            u = (rec["doc"].get("users") or {}).get(user_id) or {}
            return {"user_id": user_id, "bundle_version": int(rec["version"]), "created": False, "unchanged": True,
                    "readmitted": False, "restored": False, "previous_role": u.get("role"), "role": u.get("role"),
                    "user": self._public_user(rec["doc"], user_id, u), "changed_at": None,
                    "warnings": self._access_warnings(rec["doc"], user_id, u)}
        # feed events only after a successful publish (no orphan event); the edge drops its overlay entries
        if out["readmitted"]:
            self._feed_event("READMIT", user_id, "READMIT")
        if out["restored"]:
            self._feed_event("READMIT", user_id, "RESTORE")
        action = ("USER_CREATE" if out["created"] else "RESTORE" if out["restored"]
                  else "READMIT" if out["readmitted"] else "ACCESS_UPDATE")
        self.audit(action, kiosk_id=kiosk_id, actor=actor, user_id=user_id, bundle_version=version,
                   changes=out["diff"], consent=consent or None,
                   role_change=[out["previous_role"], out["user"].get("role")]
                   if out["previous_role"] != out["user"].get("role") else None,
                   previous_status=out["previous_status"], readmitted=out["readmitted"] or None,
                   restored=out["restored"] or None)
        log.info("access for %s %s by %s/%s -> v%s", user_id, action, kiosk_id, actor, version)
        doc = self.current()["doc"]
        return {"user_id": user_id, "bundle_version": version, "created": out["created"], "unchanged": False,
                "readmitted": out["readmitted"], "restored": out["restored"], "previous_role": out["previous_role"],
                "role": out["user"].get("role"), "user": self._public_user(doc, user_id, out["user"]),
                "changed_at": iso_z(now), "warnings": self._access_warnings(doc, user_id, out["user"])}

    @classmethod
    def _public_user(cls, doc: dict, uid: str, u: dict) -> dict:
        status, revoked_at, revoked_reason = user_state(doc, uid)
        return {"display": u.get("display"), "role": u.get("role"), **cls._entry_fields(u), "status": status,
                "revoked_at": revoked_at, "revoked_reason": revoked_reason}

    @staticmethod
    def _access_warnings(doc: dict, uid: str, u: dict) -> list[str]:
        role = (doc.get("roles") or {}).get(u.get("role")) or {}
        allowed = (set(role.get("zones") or []) | set(u.get("zones_add") or [])) - set(u.get("zones_remove") or [])
        allowed |= {z for vp in doc.get("visitor_passes") or [] if isinstance(vp, dict) and vp.get("user_id") == uid
                    for z in vp.get("zones") or []}
        out = [f"extra_windows for {z} have no effect: role {u.get('role')} has no access to {z} (add it to "
               f"zones_add)" for z in sorted(u.get("extra_windows") or {}) if z not in allowed]
        if user_state(doc, uid)[0] == "REVOKED":
            out.append("user is revoked: access changes do not lift a revocation (use Restore)")
        return out

    def rotate_codes(self, staff_id: str, count: int, *, replace_existing: bool = True, kiosk_id: str | None = None,
                     actor: str | None = None) -> dict:
        """POST /v1/admin/codes/rotate: mint `count` fresh one-time staff override codes. Only PBKDF2 hashes are
        stored; the plaintext is returned once. Documented fixture codes (OVR-001..003) are dropped."""
        documented = load_documented_override_values()
        if documented is None:  # fail secure: hygiene would strip every code, so a minted code could never work
            raise BundleRejected("CLOUD_UNAVAILABLE", "documented-code list unavailable (scripts/sign_bundle.py "
                                                      "missing from the build); cannot mint override codes",
                                 reason="CODES_UNAVAILABLE")
        length = int(self.t.override_code_length)
        now = self.clock.now().replace(microsecond=0)
        _, expires = self.bundle_times()
        valid_until = iso_z(expires + timedelta(hours=self.t.override_valid_after_expiry_h))

        def _m(doc: dict) -> dict:
            oc = doc.get("override_codes") if isinstance(doc.get("override_codes"), dict) else {}
            oc.setdefault("kdf", "PBKDF2-HMAC-SHA256")
            iterations = max(int(oc.get("iterations") or 0), int(self.t.override_pbkdf2_iterations))
            if int(oc.get("iterations") or 0) != iterations and oc.get("codes"):
                # the edge hashes with max(bundle, thresholds) iterations: codes hashed with fewer never verify
                log.warning("override codes re-based to %d PBKDF2 iterations; older codes dropped", iterations)
                oc["codes"] = []
            oc["iterations"] = iterations
            doc["override_codes"] = oc
            dropped = strip_documented_codes(doc, documented)
            if replace_existing:
                dropped += [str(c.get("code_id")) for c in oc.get("codes") or [] if c.get("staff_id") == staff_id]
                oc["codes"] = [c for c in oc.get("codes") or [] if c.get("staff_id") != staff_id]
            taken = {str(c.get("code_id")) for c in oc.get("codes") or []}
            minted = []
            stamp = now.strftime("%m%d%H%M%S")
            while len(minted) < count:
                code = f"{secrets.randbelow(10 ** length):0{length}d}"
                salt = secrets.token_hex(8)
                entry = {"code_id": f"OVR-R{stamp}-{len(minted) + 1:02d}", "staff_id": staff_id, "salt": salt,
                         "valid_until": valid_until,
                         "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), iterations).hex()}
                if entry["code_id"] in taken:
                    entry["code_id"] += f"-{secrets.token_hex(2)}"
                if is_documented(entry, iterations, documented):
                    continue  # astronomically unlikely; never hand out a documented value
                taken.add(entry["code_id"])
                oc.setdefault("codes", []).append(entry)
                minted.append({"code_id": entry["code_id"], "code": code})
            return {"minted": minted, "dropped": dropped}

        version, out = self.publish(_m, f"admin:codes:rotate:{staff_id}", meta={"actor": actor, "kiosk_id": kiosk_id})
        live = {str(c.get("code_id")) for c in (self.current()["doc"].get("override_codes") or {}).get("codes") or []}
        if not all(m["code_id"] in live for m in out["minted"]):  # defence in depth: publish-time hygiene
            raise BundleRejected("INTERNAL", "minted codes did not survive publication; nothing handed out")
        self.audit("CODES_ROTATE", kiosk_id=kiosk_id, actor=actor, staff_id=staff_id, bundle_version=version,
                   minted_code_ids=[m["code_id"] for m in out["minted"]], dropped_code_ids=out["dropped"])
        return {"staff_id": staff_id, "bundle_version": version, "codes": out["minted"],
                "dropped_code_ids": out["dropped"], "code_length": length, "valid_until": valid_until,
                "one_time": True,
                "warning": "Shown once: store these codes safely (each works once, for this staff_id only). The cloud "
                           "keeps only PBKDF2 hashes; kiosks get them with the next bundle refresh."}

    def revocations_since(self, since: int) -> tuple[int, list[dict]]:
        items = [it for _, it in self.kv.list(NS_REV) if int(it.get("seq", 0)) > since]
        items.sort(key=lambda it: int(it["seq"]))
        for it in items:
            it.pop("_rev", None)
        return self.revocation_seq(), items

    # ------------------------------------------------------------------ bundles
    def bundle_times(self) -> tuple[datetime, datetime]:
        """Lead decision (round 2): issued_at = now, expires_at = now + 12 h (capped by
        thresholds cache.bundle_max_staleness_hours)."""
        issued = self.clock.now().replace(microsecond=0)
        ttl_h = min(self.s.bundle_ttl_hours, self.t.bundle_max_staleness_hours)
        return issued, issued + timedelta(hours=ttl_h)

    def signed_bundle(self, kiosk_id: str) -> tuple[dict, str]:
        """Signed per-kiosk bundle + ETag. ETag = '"<bundle_version>"' (content version; the stamps
        change on every issue, so If-None-Match with the same version -> 304)."""
        rec = self.current()
        if kiosk_id not in (rec["doc"].get("kiosks") or {}):
            raise UnknownKiosk(kiosk_id)
        uploaded = self._stored_bundle(kiosk_id, int(rec["version"]))
        if uploaded is not None:
            return copy.deepcopy(uploaded), f'"{uploaded["bundle_version"]}"'
        bundle = filter_for_kiosk(rec["doc"], kiosk_id)
        strip_documented_codes(bundle)  # every re-sign: OVR-001..003 never get a signature
        issued, expires = self.bundle_times()
        bundle["issued_at"] = iso_z(issued)
        bundle["expires_at"] = iso_z(expires)
        # Lead decision: override codes stay usable N h past bundle expiry (expired-cache STAFF_OVERRIDE path);
        # N = thresholds.yaml fallback.staff_override.valid_after_expiry_h (same source as scripts/sign_bundle.py).
        codes_valid_until = iso_z(expires + timedelta(hours=self.t.override_valid_after_expiry_h))
        for code in (bundle.get("override_codes") or {}).get("codes") or []:
            if isinstance(code, dict):
                code["valid_until"] = codes_valid_until
        signed = sign_bundle(bundle, self.s.schedule_bundle_hmac_key, self.s.bundle_key_id)
        return signed, f'"{bundle["bundle_version"]}"'

    # ------------------------------------------------------------------ evaluation (shared code)
    def evaluate(self, user_id: str, zone: str, t0: datetime, doc: dict | None = None) -> str:
        sched_cfg = self.t.raw.get("schedule") or {}
        return self.policy.evaluate(user_id, zone, t0, doc if doc is not None else self.doc(), sched_cfg)
