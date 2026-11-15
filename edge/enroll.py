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
import logging
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
from edge.ml.templates import PINNED_TEMPLATES
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


def quality_reasons(q: FrameQuality, th) -> list[str]:
    """Enrolment-only frame gate, numbers from thresholds.yaml `quality`."""
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


async def enroll(ctx: EdgeContext, meta: EnrollMeta, jpegs: list[bytes]) -> EnrollResponse:
    th = ctx.thresholds
    eng = ctx.engine
    if is_revoked(ctx, meta.user_id):  # checked first: nothing is analysed or stored for a revoked user
        raise ApiError("FORBIDDEN", f"user {meta.user_id} is revoked; enrolment refused",
                       extra={"reason": "USER_REVOKED"})
    require_bundle(ctx)
    if erased_in_bundle(ctx, meta.user_id):  # before NOT_IN_SCHEDULE: the UI offers "Re-admit and enrol" (R-B)
        raise ApiError("INVALID_STATE", f"user {meta.user_id} was erased (DPDP) and the installed schedule bundle still "
                                        "carries that erasure: re-admit the user in the control panel (Users & "
                                        "Access), then enrol", extra={"reason": "ERASED_IN_BUNDLE"})
    entry = schedule_entry(ctx, meta.user_id)  # 409 NOT_IN_SCHEDULE unless the verified bundle lists the user
    if ctx.templates is None:
        raise ApiError("MODELS_UNAVAILABLE", "template cache unavailable (EDGE_DATA_KEY?)")
    if eng.embedder is None or eng.detector is None:
        raise ApiError("MODELS_UNAVAILABLE", "face detector / ArcFace not loaded")
    if eng.pad is None or not eng.pad.enabled:
        raise ApiError("MODELS_UNAVAILABLE", "PAD self-test not passed: enrolment requires liveness")
    if meta.card_id and not ctx.settings.card_id_pepper:
        raise ApiError("VALIDATION_ERROR", "CARD_ID_PEPPER not configured; cannot hash card_id")

    frames = await analyze_jpegs(ctx, jpegs, [now_epoch_ms()] * len(jpegs))
    pads = await _run(ctx, eng.pad_scores, frames)
    devs = await asyncio.gather(*(_run(ctx, eng.device_score, f) for f in frames))
    pass_min = float(th.get("liveness.pad.pass_min"))
    dev_cfg = th.get("liveness.device_detector")
    accepted, rejected = [], []
    for f, p, d in zip(frames, pads, devs):
        reasons = quality_reasons(f.quality, th) if f.main is not None else ["NO_FACE"]
        p_live = statistics.fmean([p.pad_v2, p.pad_v1se]) if p.pad_v2 is not None and p.pad_v1se is not None else None
        if p_live is None or p_live < pass_min:
            reasons.append("PAD_BELOW_PASS")
        if d is None or (d.device_conf >= dev_cfg["unsure_conf"] and d.device_face_containment > 0):
            reasons.append("DEVICE_NEAR_FACE")
        if reasons:
            rejected.append({"frame": f.index, "reasons": reasons, "p_live": None if p_live is None else round(p_live, 3)})
        else:
            accepted.append(f)
    min_frames = int(th.get("quality.min_usable_frames"))
    if len(accepted) < min_frames:
        raise ApiError("VALIDATION_ERROR",
                       f"only {len(accepted)} enrolment frames passed quality+liveness (need {min_frames}): {rejected}",
                       extra={"reason": "FRAMES_REJECTED", "frames_rejected": rejected})
    embs = np.stack(await asyncio.gather(*(_run(ctx, eng.embed, f) for f in accepted)))
    if not np.isfinite(embs).all() or not (np.linalg.norm(embs, axis=1) > 0).all():
        # fail closed: NaN would make every cosine comparison below False and skip the identity guards
        raise ApiError("VALIDATION_ERROR", "face embedding failed (non-finite or zero); retake the photos",
                       extra={"reason": "FRAMES_REJECTED"})
    pair = [float(a @ b) for a, b in itertools.combinations(embs, 2)]
    min_pair = min(pair) if pair else 1.0
    allow = float(th.get("match.local.allow_min_cosine"))
    if min_pair < allow:
        raise ApiError("VALIDATION_ERROR", f"enrolment frames are not one consistent identity "
                                           f"(min pairwise cosine {min_pair:.3f} < {allow})",
                       extra={"reason": "FRAMES_REJECTED"})
    gallery = ctx.templates.gallery
    for e in embs:
        hit = search(e, gallery)
        if hit.top1_user and hit.top1_user != meta.user_id and (hit.top1 or 0) >= allow:
            raise ApiError("INVALID_STATE", "this face is already enrolled under another user id", status=409,
                           extra={"reason": "FACE_ENROLLED_OTHER"})
    # Re-enrolment APPENDS templates (glasses on / off both match; the matcher takes the max over a user's
    # templates). EVERY new frame must still resemble the ORIGINAL enrolment (the pinned first templates)
    # at the local ALLOW bar (match.local.allow_min_cosine, online value), not merely the MATCH_LOW floor,
    # and not just recently appended looks, so a chain of re-enrolments cannot walk an account to a
    # different face; NaN fails closed. Same-person glasses on/off scores well above that bar.
    # DELETE /v1/enroll/{user_id} (local + cloud erasure) to replace.
    prev = ctx.templates.get(meta.user_id)
    if prev is not None:
        floor = float(th.get("match.local.allow_min_cosine"))
        worst = resemblance_to_stored(prev.embeddings()[:PINNED_TEMPLATES], embs)
        if not worst >= floor:
            raise ApiError("INVALID_STATE", f"new look does not resemble the enrolled user {meta.user_id} "
                                            f"(worst frame cosine {worst:.3f} < {floor}). To replace the look, erase the user "
                                            "(DELETE /v1/enroll/{user_id}) and enrol again with fresh consent",
                           status=409, extra={"reason": "LOOK_MISMATCH"})

    chash = card_hash(ctx.settings.card_id_pepper, meta.card_id) if meta.card_id else None
    uri: str | None = None
    secret: str | None = None
    # Re-enrolling an existing user (e.g. adding the no-glasses look) must not silently rotate the TOTP secret
    # their authenticator already holds: for an existing user only an explicit provision_totp=true rotates it.
    if meta.provision_totp and (prev is None or "provision_totp" in meta.model_fields_set):
        provision = getattr(ctx.runtime, "provision_totp", None)
        if callable(provision):  # the policy runtime's credential store owns TOTP secrets
            uri = await _run(ctx, provision, meta.user_id)
        else:
            secret = pyotp.random_base32()
            uri = pyotp.TOTP(secret, digits=int(th.get("fallback.totp.digits")),
                             interval=int(th.get("fallback.totp.period_s"))).provisioning_uri(
                name=meta.user_id, issuer_name=TOTP_ISSUER)
    warnings: list[str] = []
    schedule_role = entry.get("role") if entry else None
    if entry is not None and meta.role is not None and meta.role != schedule_role:
        warnings.append(f"requested role {meta.role!r} was NOT applied: the campus schedule says {schedule_role!r} "
                        f"(the signed schedule is the source of truth; change it in Users & Access)")
    reinstated = await _run(ctx, reinstate_after_erasure, ctx, meta.user_id)
    template_role = schedule_role or meta.role  # no runtime answer (stubs): keep the request as a label only
    user = await _run(ctx, lambda: ctx.templates.upsert(
        user_id=meta.user_id, display_name=meta.display_name, role=template_role, embeddings=embs,
        consent_version=meta.consent_version, card_id_hash=chash, totp_secret=secret, append=True))
    report_template_cache(ctx)
    cloud: dict[str, Any] | None = None
    cloud_state = "not_configured"
    mode = str(_safe_call(ctx.runtime, "mode") or "OFFLINE")
    if ctx.cloud.enabled and mode == "ONLINE":
        has_totp = uri is not None or has_local_totp(ctx, meta.user_id)
        # provision_totp=true makes the cloud mark the bundle's fallback.totp_enrolled (it also mints its own
        # unused seed); send it only when this edge holds a TOTP secret, never just because the field defaulted
        body = meta.model_dump(exclude={"card_id", "role", "provision_totp"}) | {
            "card_id_hash": chash, "provision_totp": has_totp, "totp_enrolled": has_totp}
        try:
            cloud = await ctx.cloud.enroll(body, [jpegs[f.index] for f in accepted])
        except CloudUnavailable as exc:
            cloud = {"status": None, "error": str(exc)}
        cloud = _scrub_cloud(cloud)
        cloud_state = "indexed" if _cloud_ok(cloud) else "failed"
    elif ctx.cloud.enabled:
        cloud_state = "skipped_offline"
    cloud_indexed = cloud_state == "indexed"
    bundle_version = getattr(getattr(ctx.runtime, "bundles", None), "version", None)
    if cloud_indexed:  # the cloud published a new bundle (totp_enrolled, card hash): install it now
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
    totp_active = await _run(ctx, totp_usable, ctx, meta.user_id)
    if not totp_active and (uri is not None or has_local_totp(ctx, meta.user_id)):
        warnings.append("TOTP is not active yet: the campus schedule does not mark this user TOTP-enrolled "
                        "(re-enrol while ONLINE)")
    log.info("enrolled %s (template v%s, %d frames, min pair cos %.3f, cloud %s)",
             meta.user_id, user.template_version, len(accepted), min_pair, cloud_state)
    return EnrollResponse(
        user_id=meta.user_id, template_version=user.template_version, local_cache_updated=True,
        cloud_indexed=cloud_indexed, totp_provisioning_uri=uri, frames_used=len(accepted), frames_rejected=rejected,
        min_pairwise_cosine=round(min_pair, 4), cloud=cloud, cloud_state=cloud_state, totp_active=totp_active,
        schedule_role=schedule_role, schedule_display=entry.get("display") if entry else None,
        role_requested=meta.role, role_applied=False, bundle_version=bundle_version,
        reinstated_after_erasure=reinstated, warnings=warnings,
    )


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
