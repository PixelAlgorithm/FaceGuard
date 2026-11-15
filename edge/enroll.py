"""Enrolment: liveness-gated ArcFace templates into the encrypted local cache (+ cloud when online).

Every enrolment frame must pass the edge quality checks and passive PAD (pass_min) with no device
around the face; the accepted set must be one identity (min pairwise cosine >= the local allow
threshold) and must not already match a *different* enrolled user. Before anything is analysed:
a revoked user (ADMIN / security revocation) is refused (403); a user_id that is not in the verified
schedule bundle is refused (409 NOT_IN_SCHEDULE: the gallery only admits entitled bundle users, so the
enrolment would be a permanent DENY NOT_ENROLLED). A DPDP erasure (reason ERASED) does not block a
re-enrolment once the cloud has re-admitted the user to the schedule.

ROLE: the signed schedule is the single source of truth (cloud master -> signed bundle -> edge). The
meta.role field is accepted for compatibility but never applied: the template stores the bundle role and
the response returns it as `schedule_role` (+ a warning when the requested role differs). Change a role
with PUT /v1/admin/access/users/{user_id} (edge/access.py).

A re-enrolment (appended look) must resemble the original templates at the local allow threshold (409
otherwise). Raw card IDs are stored only as HMAC-SHA256(CARD_ID_PEPPER, card_id); emails are forwarded
to the cloud, never stored on the edge.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import itertools
import json
import logging
import math
import statistics
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import numpy as np
import pyotp

from edge.access import has_local_totp, refresh_bundle
from edge.attempts import EdgeContext, _run, _safe_call, analyze_jpegs, now_epoch_ms, report_template_cache
from edge.cloud_client import CloudUnavailable
from edge.errors import ApiError
from edge.ml.matcher import search
from edge.ml.templates import TemplateStoreError
from edge.policy.schedule import revoked_at_or_before
from edge.policy.signals import FrameQuality
from edge.schemas import EnrollMeta, EnrollResponse

log = logging.getLogger("edge.enroll")
TOTP_ISSUER = "HID-Kiosk"


def card_hash(pepper: str, card_id: str) -> str:
    return hmac.new(pepper.encode(), card_id.strip().encode(), hashlib.sha256).hexdigest()


def resemblance_to_stored(stored: np.ndarray, new: np.ndarray) -> float:
    """Worst (over the new frames) best cosine to the user's stored templates, for append-mode
    re-enrolment. NaN when unusable (no finite stored template, non-finite input): callers must treat
    NaN as "does not resemble" (`not worst >= floor`), never as a pass."""
    s = np.asarray(stored, dtype=np.float32)
    n = np.asarray(new, dtype=np.float32)
    if s.ndim != 2 or n.ndim != 2 or s.shape[1] != n.shape[1] or not len(n) or not np.isfinite(n).all():
        return float("nan")
    s = s[np.isfinite(s).all(axis=1)]
    if not len(s):
        return float("nan")
    with np.errstate(all="ignore"):  # Accelerate BLAS raises spurious FP flags on macOS; result is checked
        per_new = (s @ n.T).max(axis=0)
    worst = float(per_new.min())
    return worst if np.isfinite(worst) else float("nan")


ERASED = "ERASED"


def _overlay_reason(rt: Any, user_id: str) -> str | None:
    """Reason of the revocation-feed entry for `user_id` (None = no entry)."""
    overlay = getattr(rt, "overlay", None)
    fn = getattr(overlay, "reason", None)
    if callable(fn):
        try:
            reason = fn(user_id)
        except Exception:  # noqa: BLE001 - cannot tell: treat as revoked (fail secure)
            return "UNKNOWN"
        if reason is not None:
            return str(reason)
    return "UNKNOWN" if user_id in (_safe_call(rt, "revoked_user_ids") or set()) else None


def _bundle(rt: Any) -> Mapping[str, Any] | None:
    lvb = getattr(getattr(rt, "bundles", None), "lvb", None)
    return lvb if isinstance(lvb, Mapping) else None


def is_revoked(ctx: EdgeContext, user_id: str) -> bool:
    """Revoked in the revocation feed (runtime overlay) or in the verified bundle (revocations[] or
    users[uid].revoked), effective at or before the edge clock. Revocations with reason ERASED (DPDP
    erasure) do NOT count here: an erased person may be re-admitted and re-enrolled (with fresh consent);
    whether the bundle still carries the erasure is checked separately (erased_in_bundle). A runtime that
    cannot answer -> not revoked here (the policy still denies revoked users at decision time)."""
    rt = ctx.runtime
    reason = _overlay_reason(rt, user_id)
    if reason is not None and reason != ERASED:
        return True
    lvb = _bundle(rt)
    if lvb is None:
        return False
    now = _safe_call(rt, "now") or datetime.now(UTC)
    user = (lvb.get("users") or {}).get(user_id)
    live = {**lvb, "revocations": [r for r in lvb.get("revocations") or []
                                   if not (isinstance(r, Mapping) and r.get("reason") == ERASED)]}
    return revoked_at_or_before(live, user_id, user if isinstance(user, Mapping) else None, now)


def erased_in_bundle(ctx: EdgeContext, user_id: str) -> bool:
    lvb = _bundle(ctx.runtime) or {}
    return any(isinstance(r, Mapping) and r.get("user_id") == user_id and r.get("reason") == ERASED
               for r in lvb.get("revocations") or [])


def require_bundle(ctx: EdgeContext) -> None:
    """409 NO_BUNDLE when the runtime has no verified bundle at all (nobody could be admitted)."""
    rt = ctx.runtime
    if callable(getattr(rt, "user_info", None)) and getattr(rt, "bundles", None) is not None and _bundle(rt) is None:
        raise ApiError("INVALID_STATE", "no verified campus schedule bundle is installed on this edge: nobody can "
                                        "be admitted, so enrolment is refused (refresh the bundle first)",
                       extra={"reason": "NO_BUNDLE"})


def schedule_entry(ctx: EdgeContext, user_id: str) -> dict[str, Any] | None:
    """{"user_id", "display", "role"} from the VERIFIED bundle (PolicyRuntime.user_info); else None.
    Raises 409 NO_BUNDLE / NOT_IN_SCHEDULE (R-A: PUT the access entry first, then enrol)."""
    rt = ctx.runtime
    if not callable(getattr(rt, "user_info", None)):
        return None  # runtime cannot answer (test stubs / fail-secure runtime): decisions stay fail-secure
    require_bundle(ctx)
    info = _safe_call(rt, "user_info", user_id)
    if not isinstance(info, Mapping):
        version = getattr(getattr(rt, "bundles", None), "version", None)
        raise ApiError("INVALID_STATE", f"user {user_id} is not in the campus schedule (bundle v{version}): add the "
                                        "user in the control panel (Users & Access -> Add user), then enrol",
                       extra={"reason": "NOT_IN_SCHEDULE", "bundle_version": version})
    return dict(info)


def reinstate_after_erasure(ctx: EdgeContext, user_id: str) -> bool:
    """A re-admitted, re-enrolled user: drop the stale ERASED revocation-feed entry, else the gallery filter
    keeps excluding them (DENY NOT_ENROLLED) and the next restart's apply_erasures deletes the new templates.
    Only an ERASED entry is ever removed; ADMIN / security revocations stay. Returns True if removed."""
    rt = ctx.runtime
    if _overlay_reason(rt, user_id) != ERASED:
        return False
    fn = getattr(rt, "reinstate_user", None)  # policy-engine API when present
    if callable(fn):
        return bool(fn(user_id))
    overlay = getattr(rt, "overlay", None)
    users, lock, save = getattr(overlay, "users", None), getattr(overlay, "_lock", None), \
        getattr(overlay, "_save", None)
    if not (isinstance(users, dict) and lock is not None and callable(save)):
        return False
    with lock:  # RevocationOverlay internals (edge/offline/sync.py) until PolicyRuntime.reinstate_user lands
        entry = users.get(user_id)
        if not (isinstance(entry, dict) and entry.get("reason") == ERASED):
            return False
        users.pop(user_id)
        save()
    erased = getattr(rt, "_erased", None)
    if isinstance(erased, set):
        with getattr(rt, "_lock", None) or contextlib.nullcontext():
            erased.discard(user_id)
    log.info("cleared the ERASED revocation-feed entry of re-enrolled %s", user_id)
    return True


QUALITY_METRICS = ("secondary_face_rel_size", "luma_mean", "overexposed_frac", "laplacian_var", "face_width_px",
                   "iod_px", "yaw_deg", "pitch_deg", "roll_deg")


def _finite(*values: Any) -> bool:
    """EM-12: every gate input must be a finite number (NaN makes a threshold comparison False = a pass)."""
    try:
        return all(v is not None and math.isfinite(float(v)) for v in values)
    except (TypeError, ValueError):
        return False


def quality_reasons(q: FrameQuality, th) -> list[str]:
    """Enrolment-only frame gate, numbers from thresholds.yaml `quality`. A non-finite metric rejects the frame
    (QUALITY_NONFINITE, EM-12) before any comparison."""
    if not _finite(*(getattr(q, k) for k in QUALITY_METRICS)):
        return ["QUALITY_NONFINITE"]
    c = th.get("quality")
    out = []
    if q.face_count != 1 and not (q.face_count > 1 and q.secondary_face_rel_size < c["secondary_face_min_rel_size"]):
        out.append("FACE_COUNT")
    if not c["min_luma_mean"] <= q.luma_mean <= c["max_luma_mean"] or q.overexposed_frac > c["max_overexposed_fraction"]:
        out.append("QUALITY_LOW_LIGHT")
    if q.laplacian_var < c["min_laplacian_var"]:
        out.append("QUALITY_BLUR")
    if (q.face_width_px < c["min_face_width_px"] or q.iod_px < c["min_interocular_px"]
            or abs(q.yaw_deg) > c["max_abs_yaw_deg"] or abs(q.pitch_deg) > c["max_abs_pitch_deg"]
            or abs(q.roll_deg) > c["max_abs_roll_deg"]):
        out.append("QUALITY_POSE")
    return out


def frame_reasons(q: FrameQuality | None, pad: Any, dev: Any, th) -> tuple[list[str], float | None]:
    """(reject reasons, p_live) for one enrolment frame; [] = accepted. Every comparison is written so that a
    missing or non-finite input rejects (EM-12): PAD must be finite AND >= pass_min; the device detector must
    have answered with finite values AND show no device near the face."""
    reasons = quality_reasons(q, th) if q is not None else ["NO_FACE"]
    v2, v1 = getattr(pad, "pad_v2", None), getattr(pad, "pad_v1se", None)
    p_live = statistics.fmean([v2, v1]) if _finite(v2, v1) else None
    if p_live is None or not p_live >= float(th.get("liveness.pad.pass_min")):
        reasons.append("PAD_BELOW_PASS")
    dev_cfg = th.get("liveness.device_detector")
    conf, cont = getattr(dev, "device_conf", None), getattr(dev, "device_face_containment", None)
    if dev is None or not _finite(conf, cont) or (conf >= dev_cfg["unsure_conf"] and cont > 0):
        reasons.append("DEVICE_NEAR_FACE")
    return reasons, p_live


# ---------------------------------------------------------------------------------- guards
CLOUD_ENROL_MAX_B64_BYTES = 5 * 1024 * 1024  # EAE-16: the cloud refuses bodies > 6 MB (cloud max_body_bytes)
ENROL_CROP_MAX_SIDE = 640  # face crop used only when the full frames would not fit the cloud body
REENROL_OFFLINE_KEY = "enrol.reenrol_min_cosine_offline"


def require_policy_runtime(ctx: EdgeContext) -> None:
    """EAE-14: no verified-schedule answer (fail-secure runtime / stub) -> enrolment refused, never fail-open."""
    if ctx.runtime_kind == "fail_secure" or not callable(getattr(ctx.runtime, "user_info", None)):
        raise ApiError("MODELS_UNAVAILABLE", "policy runtime unavailable: enrolment needs the verified campus "
                                             "schedule", extra={"reason": "POLICY_RUNTIME_UNAVAILABLE"})


def _parse_utc(v: Any) -> datetime | None:
    try:
        t = datetime.fromisoformat(str(v))
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def _overlay_erased_at(rt: Any, user_id: str) -> datetime | None:
    entries = _safe_call(getattr(rt, "overlay", None), "entries") or ()
    for e in entries:
        if isinstance(e, Mapping) and e.get("user_id") == user_id and e.get("reason") == ERASED:
            return _parse_utc(e.get("revoked_at"))
    return None


def require_no_pending_erasure(ctx: EdgeContext, user_id: str) -> None:
    """EAE-11: an un-lifted ERASE feed entry blocks re-enrolment unless the installed bundle was issued AFTER that
    erasure (it then no longer carries it: the user was re-admitted) or a READMIT lifted it (no entry left)."""
    rt = ctx.runtime
    if _overlay_reason(rt, user_id) != ERASED:
        return
    erased_at = _overlay_erased_at(rt, user_id)
    issued = _parse_utc((_bundle(rt) or {}).get("issued_at"))
    if erased_at is not None and issued is not None and issued > erased_at:
        return
    raise ApiError("INVALID_STATE", f"user {user_id} was erased (DPDP) and has not been re-admitted yet: re-admit the "
                                    "user in Users & Access (or refresh the bundle), then enrol",
                   extra={"reason": "ERASED_PENDING_READMIT"})


def fit_cloud_images(jpegs: list[bytes], frames: list[Any]) -> list[bytes] | None:
    """EAE-16: the images for the cloud enrol body, under CLOUD_ENROL_MAX_B64_BYTES once base64-encoded: the
    accepted frames as they are, else face crops (<= ENROL_CROP_MAX_SIDE px), else None (refuse up front)."""
    def b64_size(items: list[bytes]) -> int:
        return sum(4 * ((len(b) + 2) // 3) for b in items)

    if b64_size(jpegs) <= CLOUD_ENROL_MAX_B64_BYTES:
        return jpegs
    if len(frames) != len(jpegs):
        return None
    from edge.attempts import _face_crop_jpeg

    crops = [_face_crop_jpeg(f, max_side=ENROL_CROP_MAX_SIDE) for f in frames]
    if any(c is None for c in crops):
        return None
    fitted = [c for c in crops if c is not None]
    return fitted if b64_size(fitted) <= CLOUD_ENROL_MAX_B64_BYTES else None


def reenrol_bar(ctx: EdgeContext, online: bool) -> float:
    """EAE-05: online re-enrolment = the local allow bar (the cloud then checks identity before anything is
    committed); OFFLINE (no cloud check) = enrol.reenrol_min_cosine_offline, or at least the offline allow bar."""
    th = ctx.thresholds
    online_bar = float(th.get("match.local.allow_min_cosine"))
    if online:
        return online_bar
    offline_bar = float(th.get("offline.overrides.match.local.allow_min_cosine", online_bar))
    return max(online_bar, offline_bar, float(th.get(REENROL_OFFLINE_KEY, offline_bar)))


def guard_other_users(ctx: EdgeContext, user_id: str, embs: np.ndarray, allow: float) -> None:
    """EM-07: refuse when ANY frame matches a DIFFERENT enrolled user at the allow bar (searched with the user
    being enrolled excluded, so a near-collision behind a self top-1 is caught)."""
    gallery = ctx.templates.gallery if ctx.templates is not None else None
    if gallery is None:
        return
    for e in embs:
        hit = search(e, gallery, exclude={user_id})
        # EM-12: a non-finite similarity to another user cannot be ruled out -> refuse (fail closed)
        if hit.top1_user and (hit.top1 is None or not math.isfinite(hit.top1) or hit.top1 >= allow):
            raise ApiError("INVALID_STATE", "this face is already enrolled under another user id", status=409,
                           extra={"reason": "FACE_ENROLLED_OTHER"})


def _enrol_lock(ctx: EdgeContext) -> asyncio.Lock:
    """EM-07: collision check + upsert are one critical section per edge (two concurrent enrolments of one face
    under two user ids cannot both pass)."""
    lock = getattr(ctx, "enrol_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        ctx.enrol_lock = lock
    return lock


def user_lock(ctx: EdgeContext, user_id: str) -> asyncio.Lock:
    """EA-1: one lock per user_id held across a whole enrolment (incl. the cloud enrol) and a whole erasure (local
    delete, TOTP removal, cloud erase / queue), so an erasure can never report success while an in-flight enrolment
    re-creates the templates or indexes the face in the cloud afterwards. Event-loop only."""
    locks = getattr(ctx, "user_locks", None)
    if locks is None:
        locks = {}
        ctx.user_locks = locks
    lock = locks.get(user_id)
    if lock is None:
        lock = locks[user_id] = asyncio.Lock()
    return lock


def _refuse_revoked(ctx: EdgeContext, user_id: str) -> None:
    if is_revoked(ctx, user_id):
        raise ApiError("FORBIDDEN", f"user {user_id} is revoked; enrolment refused", extra={"reason": "USER_REVOKED"})


# ---------------------------------------------------------------------------------- analysis
async def _accepted_frames(ctx: EdgeContext, jpegs: list[bytes]) -> tuple[list[Any], list[dict[str, Any]]]:
    th, eng = ctx.thresholds, ctx.engine
    frames = await analyze_jpegs(ctx, jpegs, [now_epoch_ms()] * len(jpegs))
    pads = await _run(ctx, eng.pad_scores, frames)
    devs = await asyncio.gather(*(_run(ctx, eng.device_score, f) for f in frames))
    accepted, rejected = [], []
    for f, p, d in zip(frames, pads, devs):
        reasons, p_live = frame_reasons(f.quality if f.main is not None else None, p, d, th)
        if reasons:
            rejected.append({"frame": f.index, "reasons": reasons, "p_live": None if p_live is None else round(p_live, 3)})
        else:
            accepted.append(f)
    min_frames = int(th.get("quality.min_usable_frames"))
    if len(accepted) < min_frames:
        raise ApiError("VALIDATION_ERROR",
                       f"only {len(accepted)} enrolment frames passed quality+liveness (need {min_frames}): {rejected}",
                       extra={"reason": "FRAMES_REJECTED", "frames_rejected": rejected})
    return accepted, rejected


async def _identity_embeddings(ctx: EdgeContext, accepted: list[Any]) -> tuple[np.ndarray, float]:
    embs = np.stack(await asyncio.gather(*(_run(ctx, ctx.engine.embed, f) for f in accepted)))
    if not np.isfinite(embs).all() or not (np.linalg.norm(embs, axis=1) > 0).all():
        # fail closed: NaN would make every cosine comparison below False and skip the identity guards
        raise ApiError("VALIDATION_ERROR", "face embedding failed (non-finite or zero); retake the photos",
                       extra={"reason": "FRAMES_REJECTED"})
    pair = [float(a @ b) for a, b in itertools.combinations(embs, 2)]
    min_pair = min(pair) if pair else 1.0
    allow = float(ctx.thresholds.get("match.local.allow_min_cosine"))
    if not (math.isfinite(min_pair) and min_pair >= allow):  # EM-12: NaN never passes
        raise ApiError("VALIDATION_ERROR", f"enrolment frames are not one consistent identity "
                                           f"(min pairwise cosine {min_pair:.3f} < {allow})",
                       extra={"reason": "FRAMES_REJECTED"})
    return embs, min_pair


def _check_look(prev: Any, embs: np.ndarray, floor: float, user_id: str) -> None:
    """Re-enrolment APPENDS templates (glasses on / off). EVERY new frame must resemble the ORIGINAL enrolment
    (the pinned rows, EM-06: exactly the first enrolment's rows) at `floor` (reenrol_bar), so a chain of
    re-enrolments cannot walk an account to a different face; NaN fails closed."""
    pinned = prev.pinned_embeddings() if callable(getattr(prev, "pinned_embeddings", None)) else prev.embeddings()[:5]
    worst = resemblance_to_stored(pinned, embs)
    if not worst >= floor:
        raise ApiError("INVALID_STATE", f"new look does not resemble the enrolled user {user_id} "
                                        f"(worst frame cosine {worst:.3f} < {floor}). To replace the look, erase the user "
                                        "(DELETE /v1/enroll/{user_id}) and enrol again with fresh consent",
                       status=409, extra={"reason": "LOOK_MISMATCH"})


# ---------------------------------------------------------------------------------- cloud
def _cloud_body(meta: EnrollMeta, chash: str | None, has_totp: bool, actor: str) -> dict[str, Any]:
    """EAE-06: provision_totp / totp_enrolled are sent ONLY as true (this edge holds or provisions a secret); an
    absent key means "unchanged" in the cloud, so another kiosk's TOTP enrolment is never cleared. EAE-04: actor."""
    body = meta.model_dump(exclude={"card_id", "role", "provision_totp"}) | {"card_id_hash": chash, "actor": actor}
    return body | ({"provision_totp": True, "totp_enrolled": True} if has_totp else {})


async def _cloud_enrol(ctx: EdgeContext, body: dict[str, Any], images: list[bytes]) -> dict[str, Any]:
    try:
        cloud = await ctx.cloud.enroll(body, images)
    except CloudUnavailable as exc:
        cloud = {"status": None, "error": str(exc)}
    return _scrub_cloud(cloud) or {}


def _reenrol_refusal(cloud: dict[str, Any]) -> ApiError:
    st = cloud.get("status")
    if st is None or (isinstance(st, int) and st >= 500):
        return ApiError("CLOUD_UNAVAILABLE", "re-enrolment needs the cloud identity check, which is unreachable: "
                                             "nothing was changed, retry", extra={"reason": "CLOUD_ERROR"})
    err = ((cloud.get("body") or {}).get("error") or {}) if isinstance(cloud.get("body"), dict) else {}
    return ApiError("INVALID_STATE", f"the cloud refused the new look (HTTP {st}: {err.get('message') or 'refused'}); "
                                     "nothing was changed", status=409,
                    extra={"reason": "CLOUD_REFUSED_REENROLMENT", "cloud_status": st,
                           "cloud_reason": err.get("reason")})


async def queue_offline_enrolment(ctx: EdgeContext, user_id: str, actor: str, template_count: int) -> bool:
    """SC2-D4: an enrolment made while OFFLINE is recorded (metadata only, never images) in the runtime's encrypted
    queue and replayed to the cloud audit by replay_offline_enrolments after a successful sync."""
    fn = getattr(ctx.runtime, "queue_pending_enrolment", None)
    if not callable(fn):
        return False
    rec = {"user_id": user_id, "actor": actor, "template_count": int(template_count),
           "at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
           "model": ctx.templates.model_id if ctx.templates is not None else "unknown",
           "kiosk_id": ctx.settings.kiosk_id}
    try:
        await _run(ctx, fn, rec)
    except Exception as exc:  # noqa: BLE001 - reported as a warning, never a failed enrolment
        log.error("queueing the offline enrolment record failed: %s", type(exc).__name__)
        return False
    return True


OFFLINE_RECORD_DROP_STATUS = frozenset({400, 403, 409, 413, 422})  # will never succeed: dead-letter (logged)


def _error_reason(body: Any) -> str | None:
    err = body.get("error") if isinstance(body, Mapping) else None
    reason = err.get("reason") if isinstance(err, Mapping) else None
    return str(reason) if reason else None


def _pending_records(ctx: EdgeContext) -> list[Mapping[str, Any]]:
    pending = _safe_call(ctx.runtime, "pending_enrolments") or []
    return [r for r in pending if isinstance(r, Mapping) and isinstance(r.get("user_id"), str)]


def _record_settled(rec: Mapping[str, Any], status: Any, body: Any) -> bool:
    """True = remove the queued record: 2xx (incl. duplicate) or a permanent refusal (logged, dead-lettered).
    Kept: 401, 429, 5xx, transport errors and a 404 without a reason (route not deployed)."""
    if isinstance(status, int) and 200 <= status < 300:
        return True
    if status in OFFLINE_RECORD_DROP_STATUS or (status == 404 and _error_reason(body)):
        log.error("offline enrolment record for %s refused by the cloud (HTTP %s): dropped", rec["user_id"], status)
        return True
    return False


async def replay_offline_enrolments(ctx: EdgeContext) -> int:
    """Replay queued offline-enrolment records (POST /v1/enroll/offline-record, idempotent on the cloud) through
    the async CloudClient. Returns the number delivered. Never raises."""
    clear = getattr(ctx.runtime, "clear_pending_enrolment", None)
    records = _pending_records(ctx)
    if not records or not ctx.cloud.enabled or not callable(clear):
        return 0
    done = 0
    for rec in records:
        try:
            res = await ctx.cloud.offline_enrolment_record(dict(rec))
        except CloudUnavailable:
            break  # unreachable: the next sync retries
        if _record_settled(rec, res.get("status"), res.get("body")):
            await _run(ctx, clear, rec["user_id"])
            done += 1 if 200 <= int(res.get("status") or 0) < 300 else 0
    return done


OFFLINE_RECORD_SYNC_TIMEOUT_S = 3.0


def replay_offline_enrolments_sync(ctx: EdgeContext) -> int:
    """Probe offline-e2e F2: the same replay, synchronously on the runtime's sync thread BEFORE the decision batch
    (runtime.add_pre_sync_hook), so the cloud knows the offline template when it judges that user's offline
    ALLOWs (OFFLINE_TEMPLATE_UNCONFIRMED). Own short-lived signed httpx.Client (never the runtime's). Never raises."""
    import httpx

    from edge.cloud_client import auth_headers, new_request_id

    clear = getattr(ctx.runtime, "clear_pending_enrolment", None)
    records = _pending_records(ctx)
    if not records or not ctx.cloud.enabled or not callable(clear):
        return 0
    done = 0
    try:
        with httpx.Client(base_url=ctx.settings.cloud_api_url, verify=ctx.cloud.tls_verify,
                          transport=_sync_transport(ctx), timeout=OFFLINE_RECORD_SYNC_TIMEOUT_S) as client:
            for rec in records:
                body = json.dumps({**rec, "request_id": new_request_id()}, separators=(",", ":")).encode()
                path = "/v1/enroll/offline-record"
                headers = {**auth_headers(ctx.settings, "POST", path, body), "Content-Type": "application/json"}
                try:
                    resp = client.post(path, content=body, headers=headers)
                except httpx.HTTPError:
                    break
                parsed = _json_or_none(resp)
                if _record_settled(rec, resp.status_code, parsed):
                    clear(rec["user_id"])
                    done += 1 if 200 <= resp.status_code < 300 else 0
    except Exception as exc:  # noqa: BLE001 - a hook must never break the sync cycle
        log.error("offline enrolment replay failed: %s", type(exc).__name__)
    return done


def _sync_transport(ctx: EdgeContext) -> Any:
    """The CloudClient's injected transport when it can serve a sync client (tests: httpx.MockTransport)."""
    t = getattr(ctx.cloud, "_transport", None)
    return t if t is not None and callable(getattr(t, "handle_request", None)) else None


def _json_or_none(resp: Any) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


# ---------------------------------------------------------------------------------- enrolment
async def _local_secret(ctx: EdgeContext, meta: EnrollMeta, prev: Any) -> tuple[bool, str | None, str | None]:
    """(rotate TOTP?, template-held secret, its URI). Re-enrolling an existing user (e.g. adding the no-glasses
    look) must not silently rotate the TOTP secret their authenticator holds: only an explicit provision_totp=true
    rotates it. With a policy runtime the secret is provisioned AFTER the template commit (EAE-13)."""
    th = ctx.thresholds
    rotate = bool(meta.provision_totp and (prev is None or "provision_totp" in meta.model_fields_set))
    if not rotate or callable(getattr(ctx.runtime, "provision_totp", None)):
        return rotate, None, None
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret, digits=int(th.get("fallback.totp.digits")),
                     interval=int(th.get("fallback.totp.period_s"))).provisioning_uri(
        name=meta.user_id, issuer_name=TOTP_ISSUER)
    return rotate, secret, uri


async def _commit(ctx: EdgeContext, meta: EnrollMeta, embs: np.ndarray, template_role: str | None,
                  chash: str | None, secret: str | None) -> Any:
    try:
        user = await _run(ctx, lambda: ctx.templates.upsert(
            user_id=meta.user_id, display_name=meta.display_name, role=template_role, embeddings=embs,
            consent_version=meta.consent_version, card_id_hash=chash, totp_secret=secret, append=True))
    except TemplateStoreError as exc:
        raise ApiError("MODELS_UNAVAILABLE", f"enrolment NOT stored (template store write failed: {exc}); nothing "
                                             "was changed, retry", extra={"reason": "LOCAL_WRITE_FAILED"}) from exc
    report_template_cache(ctx)
    return user


def _preflight(ctx: EdgeContext, meta: EnrollMeta) -> dict[str, Any] | None:
    require_policy_runtime(ctx)
    _refuse_revoked(ctx, meta.user_id)  # checked first: nothing is analysed or stored for a revoked user
    require_bundle(ctx)
    if erased_in_bundle(ctx, meta.user_id):  # before NOT_IN_SCHEDULE: the UI offers "Re-admit and enrol" (R-B)
        raise ApiError("INVALID_STATE", f"user {meta.user_id} was erased (DPDP) and the installed schedule bundle still "
                                        "carries that erasure: re-admit the user in the control panel (Users & "
                                        "Access), then enrol", extra={"reason": "ERASED_IN_BUNDLE"})
    require_no_pending_erasure(ctx, meta.user_id)
    entry = schedule_entry(ctx, meta.user_id)  # 409 NOT_IN_SCHEDULE unless the verified bundle lists the user
    eng = ctx.engine
    if ctx.templates is None:
        raise ApiError("MODELS_UNAVAILABLE", "template cache unavailable (EDGE_DATA_KEY?)")
    if eng.embedder is None or eng.detector is None:
        raise ApiError("MODELS_UNAVAILABLE", "face detector / ArcFace not loaded")
    if eng.pad is None or not eng.pad.enabled:
        raise ApiError("MODELS_UNAVAILABLE", "PAD self-test not passed: enrolment requires liveness")
    if meta.card_id and not ctx.settings.card_id_pepper:
        raise ApiError("VALIDATION_ERROR", "CARD_ID_PEPPER not configured; cannot hash card_id")
    return entry


async def enroll(ctx: EdgeContext, meta: EnrollMeta, jpegs: list[bytes],
                 actor: str = "legacy:admin_token") -> EnrollResponse:
    async with user_lock(ctx, meta.user_id):  # EA-1: serialised with DELETE /v1/enroll/{user_id}
        return await _enroll_locked(ctx, meta, jpegs, actor)


async def _enroll_locked(ctx: EdgeContext, meta: EnrollMeta, jpegs: list[bytes], actor: str) -> EnrollResponse:
    entry = _preflight(ctx, meta)
    accepted, rejected = await _accepted_frames(ctx, jpegs)
    embs, min_pair = await _identity_embeddings(ctx, accepted)
    online = ctx.cloud.enabled and str(_safe_call(ctx.runtime, "mode") or "OFFLINE") == "ONLINE"
    images = [jpegs[f.index] for f in accepted]
    if online:
        images = fit_cloud_images(images, accepted)
        if images is None:
            raise ApiError("PAYLOAD_TOO_LARGE", "enrolment photos are too large for the cloud even as face crops: "
                                                "retake them at a lower resolution", extra={"reason": "CLOUD_BODY_CAP"})
    chash = card_hash(ctx.settings.card_id_pepper, meta.card_id) if meta.card_id else None
    schedule_role = entry.get("role") if entry else None
    warnings: list[str] = []
    if entry is not None and meta.role is not None and meta.role != schedule_role:
        warnings.append(f"requested role {meta.role!r} was NOT applied: the campus schedule says {schedule_role!r} "
                        f"(the signed schedule is the source of truth; change it in Users & Access)")
    async with _enrol_lock(ctx):
        guard_other_users(ctx, meta.user_id, embs, float(ctx.thresholds.get("match.local.allow_min_cosine")))
        prev = ctx.templates.get(meta.user_id)
        if prev is not None:
            _check_look(prev, embs, reenrol_bar(ctx, online), meta.user_id)
        rotate, secret, uri = await _local_secret(ctx, meta, prev)
        has_totp = rotate or has_local_totp(ctx, meta.user_id)
        cloud: dict[str, Any] | None = None
        if prev is not None and online:  # EAE-05: cloud identity check BEFORE the local append
            cloud = await _cloud_enrol(ctx, _cloud_body(meta, chash, has_totp, actor), images)
            if not _cloud_ok(cloud):
                raise _reenrol_refusal(cloud)
        _refuse_revoked(ctx, meta.user_id)  # EAE-11: re-checked right before the write
        require_no_pending_erasure(ctx, meta.user_id)
        reinstated = await _reinstate(ctx, meta.user_id)
        user = await _commit(ctx, meta, embs, schedule_role or meta.role, chash, secret)
        if rotate and secret is None:  # EAE-13: rotate the runtime-held secret only after the commit
            uri = await _run(ctx, ctx.runtime.provision_totp, meta.user_id)
    if prev is None and online:
        cloud = await _cloud_enrol(ctx, _cloud_body(meta, chash, has_totp, actor), images)
    cloud_state = _cloud_state(ctx, online, cloud)
    bundle_version = await _after_cloud(ctx, cloud, cloud_state, warnings)
    if cloud_state == "skipped_offline" and not await queue_offline_enrolment(ctx, meta.user_id, actor, len(embs)):
        warnings.append("the offline enrolment could not be queued for the cloud audit (policy runtime without the "
                        "pending-enrolment queue)")
    totp_active = await _run(ctx, totp_usable, ctx, meta.user_id)
    if not totp_active and (uri is not None or has_local_totp(ctx, meta.user_id)):
        warnings.append("TOTP is not active yet: the campus schedule does not mark this user TOTP-enrolled "
                        "(re-enrol while ONLINE)")
    log.info("enrolled %s (template v%s, %d frames, min pair cos %.3f, cloud %s, actor %s)",
             meta.user_id, user.template_version, len(accepted), min_pair, cloud_state, actor)
    return EnrollResponse(
        user_id=meta.user_id, template_version=user.template_version, local_cache_updated=True,
        cloud_indexed=cloud_state == "indexed", totp_provisioning_uri=uri, frames_used=len(accepted),
        frames_rejected=rejected, min_pairwise_cosine=round(min_pair, 4), cloud=cloud, cloud_state=cloud_state,
        totp_active=totp_active, schedule_role=schedule_role, schedule_display=entry.get("display") if entry else None,
        role_requested=meta.role, role_applied=False, bundle_version=bundle_version,
        reinstated_after_erasure=reinstated, warnings=warnings,
    )


async def _reinstate(ctx: EdgeContext, user_id: str) -> bool:
    """reinstate_after_erasure; the runtime raises RuntimeError when an earlier erasure purge of this user is still
    failing (EO-05: the old templates must be gone before new ones are accepted) -> refused, nothing stored."""
    try:
        return await _run(ctx, reinstate_after_erasure, ctx, user_id)
    except RuntimeError as exc:
        raise ApiError("MODELS_UNAVAILABLE", f"the earlier erasure of {user_id} has not been fully applied on this edge "
                                             "yet; nothing was stored, retry", extra={"reason": "ERASURE_PENDING"}) from exc


def _cloud_state(ctx: EdgeContext, online: bool, cloud: dict[str, Any] | None) -> str:
    if not ctx.cloud.enabled:
        return "not_configured"
    if not online:
        return "skipped_offline"
    return "indexed" if _cloud_ok(cloud) else "failed"


async def _after_cloud(ctx: EdgeContext, cloud: dict[str, Any] | None, cloud_state: str,
                       warnings: list[str]) -> int | None:
    """Install the bundle the cloud published (totp_enrolled, card hash) and add the cloud-state warnings."""
    bundle_version = getattr(getattr(ctx.runtime, "bundles", None), "version", None)
    if cloud_state == "indexed":
        want = ((cloud or {}).get("body") or {}).get("bundle_version")
        refreshed = await refresh_bundle(ctx, want if isinstance(want, int) and not isinstance(want, bool) else None)
        bundle_version = refreshed.get("installed_version")
        if refreshed.get("error"):
            warnings.append(f"bundle refresh after enrolment failed ({refreshed['error']}); the periodic refresh "
                            "will pick it up")
    elif cloud_state == "failed":
        st = (cloud or {}).get("status")
        warnings.append(f"NOT indexed in the cloud (cloud enrol {'HTTP ' + str(st) if st else 'unreachable'}): while "
                        "ONLINE, Rekognition is authoritative, so this user is NOT_ENROLLED online until re-enrolled "
                        "with the cloud reachable")
    elif cloud_state == "skipped_offline":
        warnings.append("kiosk is OFFLINE: enrolled on this edge only. Once ONLINE, Rekognition is authoritative and "
                        "this user is NOT_ENROLLED until re-enrolled while ONLINE")
    return bundle_version


def totp_usable(ctx: EdgeContext, user_id: str) -> bool:
    """TOTP is offered at the kiosk only when the edge holds the secret AND the installed bundle marks the user
    fallback.totp_enrolled (PolicyRuntime.totp_status "usable")."""
    st = _safe_call(ctx.runtime, "totp_status", user_id)
    if isinstance(st, Mapping) and "usable" in st:
        return bool(st["usable"])
    u = ((_bundle(ctx.runtime) or {}).get("users") or {}).get(user_id)
    flag = isinstance(u, Mapping) and bool((u.get("fallback") or {}).get("totp_enrolled"))
    return flag and has_local_totp(ctx, user_id, ctx.templates.get(user_id) if ctx.templates else None)


_SECRET_KEYS = frozenset({"totp_provisioning_uri", "totp_secret", "totp_seed", "secret", "otpauth_uri"})


def _scrub_cloud(cloud: dict[str, Any] | None) -> dict[str, Any] | None:
    """The browser must see exactly one TOTP secret (the edge's): drop secret-bearing keys from the cloud body."""
    if not isinstance(cloud, dict) or not isinstance(cloud.get("body"), dict):
        return cloud
    return {**cloud, "body": {k: v for k, v in cloud["body"].items() if k not in _SECRET_KEYS}}


def _cloud_ok(cloud: dict[str, Any] | None) -> bool:
    body_ok = isinstance(cloud, dict) and isinstance(cloud.get("body"), dict)
    return bool(cloud and cloud.get("status") in (200, 201) and body_ok and cloud["body"].get("cloud_indexed", True))
