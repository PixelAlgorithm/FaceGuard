"""Staff override codes (SC2 D8): minting, staff_id ownership, per-kiosk scoping and one-time consumption.

Split out of schedule_service.py (behaviour unchanged). The master schedule document holds two master-only keys
that never reach a bundle: STAFF_REGISTRY ({staff_id: {owner_kiosk_id, registered_at}}; a staff_id belongs to
the kiosk that first rotates it) and CONSUMED_CODES (codes used by a synced STAFF_OVERRIDE ALLOW, listed in the
signed `consumed_code_ids` of every bundle until their original valid_until).

ScheduleService keeps the public methods (rotate_codes, consume_code, code_owner, code_kiosk) as thin wrappers.
This module never imports schedule_service at module level (schedule_service imports it): the service is passed
in, and BundleRejected is resolved lazily.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import secrets
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from ..clock import iso_z, parse_ts
from .code_hygiene import is_documented, strip_documented_codes

if TYPE_CHECKING:
    from .schedule_service import BundleRejected, ScheduleService

log = logging.getLogger("hid.cloud.schedule")

# Staff override codes (SC2 D8): a staff_id belongs to the kiosk that first rotates it; per-staff active-code cap
MAX_ACTIVE_CODES_PER_STAFF = 10
STAFF_REGISTRY = "staff_registry"  # master-only key {staff_id: {owner_kiosk_id, registered_at}} (never in a bundle)
CONSUMED_CODES = "consumed_codes"  # master-only key [{code_id, valid_until, consumed_at, kiosk_id, attempt_id}]
# master-only key [{code_id, staff_id, valid_until}]: codes a rotation dropped from the master that offline kiosks may
# still hold in a cached bundle until valid_until (still "known": a synced use of one is consumed, not "unknown")
RETIRED_CODES = "retired_codes"
MASTER_ONLY_KEYS = (STAFF_REGISTRY, CONSUMED_CODES, RETIRED_CODES)
CODE_ROTATE_WARNING = ("Shown once: store these codes safely (each works once, for this staff_id only). The cloud "
                       "keeps only PBKDF2 hashes; kiosks get them with the next bundle refresh.")


class _AlreadyConsumed(Exception):  # noqa: N818 - control flow: the code is already consumed, do not publish
    pass


class UnknownCode(LookupError):
    """consume_code: the cloud never minted (or no longer knows) this code_id; nothing is published (CA-04)."""


def _rejected(code: str, message: str, reason: str | None = None) -> BundleRejected:
    """A schedule-service BundleRejected (imported lazily: schedule_service imports this module)."""
    from .schedule_service import BundleRejected

    return BundleRejected(code, message, reason=reason)


def check_override_codes(oc: Any) -> None:
    """Shape check of a document's / uploaded bundle's override_codes {kdf, iterations, codes[]}."""
    if oc is None:
        return
    if not isinstance(oc, dict):
        raise _rejected("VALIDATION_ERROR", "override_codes must be an object {kdf, iterations, codes[]}")
    it = oc.get("iterations")
    if it is not None and (not isinstance(it, int) or isinstance(it, bool) or it < 1):
        raise _rejected("VALIDATION_ERROR", "override_codes.iterations must be a positive integer")
    codes = oc.get("codes")
    if codes is not None and not isinstance(codes, list):
        raise _rejected("VALIDATION_ERROR", "override_codes.codes must be a list")
    for i, c in enumerate(codes or []):
        if not isinstance(c, dict) or not all(isinstance(c.get(f), str) for f in ("code_id", "staff_id", "salt",
                                                                                     "hash")):
            raise _rejected("VALIDATION_ERROR", f"override_codes.codes[{i}] needs string code_id / staff_id / "
                                                "salt / hash")


def codes_for_kiosk(doc: dict, kiosk_id: str) -> dict:
    """Override codes a kiosk may honour: a staff_id registered to another kiosk (owner_kiosk_id, SC2 D8) never
    reaches this kiosk's bundle (an unscoped code opened every zone of the campus). Unregistered staff ids (codes
    from an operator-signed upload or a legacy master) keep the previous behaviour."""
    oc = copy.deepcopy(doc.get("override_codes") or {})
    registry = doc.get(STAFF_REGISTRY) or {}
    if isinstance(oc, dict) and isinstance(oc.get("codes"), list) and registry:
        oc["codes"] = [c for c in oc["codes"] if not isinstance(c, dict)
                       or (registry.get(c.get("staff_id")) or {}).get("owner_kiosk_id", kiosk_id) == kiosk_id]
    return oc


def consumed_ids(doc: dict, at: datetime) -> list[str]:
    """Code ids consumed by a synced STAFF_OVERRIDE ALLOW whose original valid_until is still ahead of `at`."""
    out = []
    for c in doc.get(CONSUMED_CODES) or []:
        try:
            if isinstance(c, dict) and parse_ts(str(c.get("valid_until"))) > at:
                out.append(str(c.get("code_id")))
        except ValueError:
            out.append(str(c.get("code_id")))  # unparsable expiry: keep listing it (fail secure)
    return sorted(set(out))


def _live_entries(entries: Any, at: datetime) -> list[dict]:
    out = []
    for c in entries or []:
        if not isinstance(c, dict):
            continue
        try:
            if parse_ts(str(c.get("valid_until"))) > at:
                out.append(c)
        except ValueError:
            out.append(c)  # unparsable expiry: keep (fail secure)
    return out


def _retire(doc: dict, dropped: list[dict], valid_until: str, now: datetime) -> None:
    """Remember codes a rotation removed (ids + staff only, no hashes) until any cached copy has expired."""
    kept = _live_entries(doc.get(RETIRED_CODES), now)
    have = {c.get("code_id") for c in kept}
    kept += [{"code_id": str(c.get("code_id")), "staff_id": c.get("staff_id"), "valid_until": valid_until}
             for c in dropped if isinstance(c, dict) and c.get("code_id") not in have]
    doc[RETIRED_CODES] = kept


def claim_staff_id(doc: dict, staff_id: str, kiosk_id: str | None, now: datetime) -> None:
    """Bind `staff_id` to `kiosk_id` in the master staff registry on first rotation (409 STAFF_ID_TAKEN when
    another kiosk owns it). Writes a new registry dict into `doc` (the publish copy)."""
    registry = doc.get(STAFF_REGISTRY) if isinstance(doc.get(STAFF_REGISTRY), dict) else {}
    owner = (registry.get(staff_id) or {}).get("owner_kiosk_id")
    if owner is not None and kiosk_id is not None and owner != kiosk_id:
        raise _rejected("INVALID_STATE", f"{staff_id} belongs to another kiosk; pick a different staff_id",
                        reason="STAFF_ID_TAKEN")
    if owner is None and kiosk_id is not None:
        registry = {**registry, staff_id: {"owner_kiosk_id": kiosk_id, "registered_at": iso_z(now)}}
    doc[STAFF_REGISTRY] = registry


def _rebase_iterations(oc: dict, iterations: int) -> list[dict]:
    """Drop every code hashed with a different PBKDF2 iteration count; returns the dropped entries."""
    if int(oc.get("iterations") or 0) == iterations or not oc.get("codes"):
        return []
    # the edge hashes with max(bundle, thresholds) iterations: codes hashed with fewer never verify
    log.warning("override codes re-based to %d PBKDF2 iterations; older codes dropped", iterations)
    rebased = [c for c in oc["codes"] if isinstance(c, dict)]
    oc["codes"] = []
    return rebased


def _mint(oc: dict, staff_id: str, count: int, *, length: int, iterations: int, valid_until: str,
          kiosk_id: str | None, now: datetime, documented: tuple[str, ...]) -> list[dict]:
    """Append `count` fresh hashed codes for `staff_id` to `oc`; returns [{code_id, code}] (plaintext, once)."""
    taken = {str(c.get("code_id")) for c in oc.get("codes") or []}
    minted: list[dict] = []
    stamp = now.strftime("%m%d%H%M%S")
    while len(minted) < count:
        code = f"{secrets.randbelow(10 ** length):0{length}d}"
        salt = secrets.token_hex(8)
        entry = {"code_id": f"OVR-R{stamp}-{len(minted) + 1:02d}", "staff_id": staff_id, "salt": salt,
                 "valid_until": valid_until,
                 "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), iterations).hex()}
        if kiosk_id is not None:  # signed scope: the edge refuses the code at any other kiosk (F09)
            entry["kiosk_ids"] = [kiosk_id]
        if entry["code_id"] in taken:
            entry["code_id"] += f"-{secrets.token_hex(2)}"
        if is_documented(entry, iterations, documented):
            continue  # astronomically unlikely; never hand out a documented value
        taken.add(entry["code_id"])
        oc.setdefault("codes", []).append(entry)
        minted.append({"code_id": entry["code_id"], "code": code})
    return minted


def _check_active_cap(oc: dict, staff_id: str) -> None:
    active = sum(1 for c in oc.get("codes") or [] if isinstance(c, dict) and c.get("staff_id") == staff_id)
    if active > MAX_ACTIVE_CODES_PER_STAFF:
        raise _rejected("VALIDATION_ERROR", f"{staff_id} would hold {active} active codes (max "
                                            f"{MAX_ACTIVE_CODES_PER_STAFF}); rotate with "
                                            "replace_existing: true", reason="TOO_MANY_ACTIVE_CODES")


def rotate_codes(svc: ScheduleService, staff_id: str, count: int, *, documented: tuple[str, ...] | None,
                 replace_existing: bool = True, kiosk_id: str | None = None, actor: str | None = None,
                 audit_meta: dict | None = None) -> dict:
    """POST /v1/admin/codes/rotate (see ScheduleService.rotate_codes). `documented` = the publicly documented
    override values (None when the list is unavailable: fail secure, nothing is minted)."""
    if documented is None:  # fail secure: hygiene would strip every code, so a minted code could never work
        raise _rejected("CLOUD_UNAVAILABLE", "documented-code list unavailable (scripts/sign_bundle.py "
                                             "missing from the build); cannot mint override codes",
                        reason="CODES_UNAVAILABLE")
    length = int(svc.t.override_code_length)
    now = svc.clock.now().replace(microsecond=0)
    _, expires = svc.bundle_times()
    valid_until = iso_z(expires + timedelta(hours=svc.t.override_valid_after_expiry_h))

    def _m(doc: dict) -> dict:
        claim_staff_id(doc, staff_id, kiosk_id, now)
        oc = doc.get("override_codes") if isinstance(doc.get("override_codes"), dict) else {}
        oc.setdefault("kdf", "PBKDF2-HMAC-SHA256")
        iterations = max(int(oc.get("iterations") or 0), int(svc.t.override_pbkdf2_iterations))
        rebased = _rebase_iterations(oc, iterations)
        oc["iterations"] = iterations
        doc["override_codes"] = oc
        documented_ids = strip_documented_codes(doc, documented)
        replaced = [c for c in oc.get("codes") or [] if c.get("staff_id") == staff_id] if replace_existing else []
        if replace_existing:
            oc["codes"] = [c for c in oc.get("codes") or [] if c.get("staff_id") != staff_id]
        _retire(doc, rebased + replaced, valid_until, now)  # documented codes are never "known"
        dropped = [str(c.get("code_id")) for c in rebased] + documented_ids + \
            [str(c.get("code_id")) for c in replaced]
        minted = _mint(oc, staff_id, count, length=length, iterations=iterations, valid_until=valid_until,
                       kiosk_id=kiosk_id, now=now, documented=documented)
        _check_active_cap(oc, staff_id)
        return {"minted": minted, "dropped": dropped}

    version, out = svc.publish(_m, f"admin:codes:rotate:{staff_id}", meta={"actor": actor, "kiosk_id": kiosk_id})
    live = {str(c.get("code_id")) for c in (svc.current()["doc"].get("override_codes") or {}).get("codes") or []}
    if not all(m["code_id"] in live for m in out["minted"]):  # defence in depth: publish-time hygiene
        raise _rejected("INTERNAL", "minted codes did not survive publication; nothing handed out")
    svc.audit("CODES_ROTATE", kiosk_id=kiosk_id, actor=actor, staff_id=staff_id, bundle_version=version,
              minted_code_ids=[m["code_id"] for m in out["minted"]], dropped_code_ids=out["dropped"],
              **(audit_meta or {}))
    return {"staff_id": staff_id, "bundle_version": version, "codes": out["minted"],
            "dropped_code_ids": out["dropped"], "code_length": length, "valid_until": valid_until,
            "one_time": True, "warning": CODE_ROTATE_WARNING}


def consume_code(svc: ScheduleService, code_id: str, *, kiosk_id: str, attempt_id: str) -> int | None:
    """A synced STAFF_OVERRIDE ALLOW used `code_id` (see ScheduleService.consume_code). Returns the new
    bundle_version, or None when it was already consumed. UnknownCode when the cloud never minted it (master
    codes, recently retired codes): an arbitrary kiosk-reported id never enters every kiosk's signed bundle."""
    now = svc.clock.now().replace(microsecond=0)
    _, expires = svc.bundle_times()
    latest_valid = expires + timedelta(hours=svc.t.override_valid_after_expiry_h)  # what any issued copy says

    def _m(doc: dict) -> None:
        consumed = [c for c in doc.get(CONSUMED_CODES) or [] if isinstance(c, dict)
                    and str(c.get("code_id")) in set(consumed_ids(doc, now))]
        if any(c.get("code_id") == code_id for c in consumed):
            raise _AlreadyConsumed
        oc = doc.get("override_codes") if isinstance(doc.get("override_codes"), dict) else {}
        codes = oc.get("codes") or []
        hit = next((c for c in codes if isinstance(c, dict) and c.get("code_id") == code_id), None)
        if hit is None:
            hit = next((c for c in _live_entries(doc.get(RETIRED_CODES), now) if c.get("code_id") == code_id), None)
            if hit is None:
                raise UnknownCode(code_id)
        else:
            oc["codes"] = [c for c in codes if c is not hit]
        consumed.append({"code_id": code_id, "valid_until": iso_z(latest_valid), "consumed_at": iso_z(now),
                         "kiosk_id": kiosk_id, "attempt_id": attempt_id,
                         "staff_id": (hit or {}).get("staff_id")})
        doc[CONSUMED_CODES] = consumed

    try:
        version, _ = svc.publish(_m, f"sync:code-consumed:{code_id}")
    except _AlreadyConsumed:
        return None
    svc.audit("CODE_CONSUMED", kiosk_id=kiosk_id, code_id=code_id, attempt_id=attempt_id,
              bundle_version=version, actor_assurance="device", via=f"kiosk:{kiosk_id}")
    return version


def code_owner(doc: dict, code_id: str) -> str | None:
    """staff_id a known code was minted for (master codes or the consumed list); None when unknown."""
    for c in [*((doc.get("override_codes") or {}).get("codes") or []), *(doc.get(CONSUMED_CODES) or []),
              *(doc.get(RETIRED_CODES) or [])]:
        if isinstance(c, dict) and c.get("code_id") == code_id:
            return c.get("staff_id")
    return None


def code_kiosk(doc: dict, code_id: str) -> str | None:
    """Owner kiosk of a known code's staff_id (staff registry); None when unknown or unregistered."""
    staff = code_owner(doc, code_id)
    return ((doc.get(STAFF_REGISTRY) or {}).get(staff) or {}).get("owner_kiosk_id") if staff else None
