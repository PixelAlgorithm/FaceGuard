"""docs/POLICY_TEST_CASES.md §8 invariants P01-P13 (P10 lives in test_ratelimit.py), seeded fuzzing.

The generator randomises every signal (incl. None / NaN / boundary values), mode, kiosk / user / time,
bundle state (fresh / fixed stamps / tampered / unsigned / missing), refresh age, RNG draw and config
toggles. Seeds are fixed so failures are reproducible.

Every invariant runs under three config profiles (lead 2026-11-14): `fixture` = the documented rules
(builders.DOC_BASELINE_PATCH), `shipped` = config/thresholds.yaml exactly as shipped, and `advisory` = the
most permissive operator profile in use today (flash / moire / RGB-M2 advisory, no random challenge, unknown
camera label not UNSURE). The invariants are properties of the code, so they must hold for all three.
"""

from __future__ import annotations

import copy
import math
import random

import pytest

from edge.policy import engine
from edge.policy.codes import ALL_CODES, DENY_TYPE, HARD_LIVENESS_CODES
from edge.policy.engine import DECISION_RANK, evaluate
from edge.policy.schedule import cache_state, zone_risk
from edge.policy.signals import CameraMeta
from edge.policy.tests.builders import KIOSK, OB, B, Scn, StubRng, load_example_bundle, tampered
from edge.policy.tests.builders import bundle_signed_at as signed_at
from edge.policy.tests.test_stepup import Flow
from edge.policy.thresholds import RISK_LEVELS

N = 1500
USERS = ["u_3c4d", "u_1a2b", "u_7a8b", "u_a3b4", "u_e1f2", "u_9c0d", "u_c5d6", "u_5e6f", "u_zz99"]
NAN = math.nan


def pick(r, xs):
    return xs[r.randrange(len(xs))]


PROFILES: dict[str, dict | None] = {
    "fixture": None,  # builders default: DOC_BASELINE_PATCH
    "shipped": {},  # config/thresholds.yaml as shipped
    "advisory": {
        "liveness": {"flash": {"enforce": False}, "moire": {"enforce": False}, "mask": {"m2_rgb_enforce": False}},
        "challenge": {"random_rate": 0.0}, "offline": {"overrides": {"challenge": {"random_rate": 0.0}}},
        "injection": {"unknown_label_is_unsure": False},
    },
}


def random_scn(r: random.Random, profile: dict | None = None) -> Scn:
    scn = B() if r.random() < 0.5 else OB()
    if profile is not None:
        scn.cfg_patch = copy.deepcopy(profile)
    user = pick(r, USERS)
    when = ("2026-11-14T10:05" if r.random() < 0.5 else
            f"2026-11-{pick(r, ['14', '15', '16', '18', '20'])}T"
            f"{r.randint(0, 23):02d}:{pick(r, [0, 5, 14, 15, 30, 44, 45, 50, 59]):02d}")
    scn.who(user, pick(r, list(KIOSK)), when)
    _perturb(scn, r, user)
    return scn


def _perturb(scn: Scn, r: random.Random, user: str) -> None:
    """Apply 0-3 random perturbations (mostly clean inputs, so every outcome class occurs)."""
    ops = list(_OPS)
    r.shuffle(ops)
    for op in ops[: pick(r, [0, 0, 1, 1, 2, 3])]:
        op(scn, r, user)


def _op_bundle(scn, r, user):
    roll = r.random()
    if roll < 0.15:
        scn.fixed()
    elif roll < 0.20:
        scn.bundle = tampered(signed_at(scn.eff_now))
    elif roll < 0.23:
        scn.bundle = load_example_bundle()  # unsigned
    elif roll < 0.25:
        scn.no_bundle = True


def _op_refresh(scn, r, user):
    scn.refresh_age_s = pick(r, [None, 0, 300, 1799, 1800, 1801, 3600])


def _op_pad(scn, r, user):
    scn.pad = [pick(r, [None, NAN, 0.0, 0.1, 0.25, 0.3, 0.31, 0.5, 0.79, 0.8, 0.84, 0.85, 0.9, 0.95, 1.0])
               for _ in range(5)]


def _op_quality(scn, r, user):
    scn.luma = [pick(r, [120.0] * 6 + [40.0, 59.0, 60.0, 210.0, 211.0, NAN]) for _ in range(5)]
    scn.lapvar = [pick(r, [150.0] * 6 + [30.0, 79.0, 80.0]) for _ in range(5)]
    scn.yaw = [pick(r, [5.0] * 6 + [0.0, 25.0, 26.0, 35.0]) for _ in range(5)]
    scn.secondary = [pick(r, [0.0] * 8 + [0.3, 0.5, 0.7]) for _ in range(5)]
    scn.recapture_count = pick(r, [0, 1, 2, 3])


def _op_device_moire_ring(scn, r, user):
    scn.device = [pick(r, [(0.0, 0.0)] * 6 + [(0.24, 0.5), (0.25, 0.5), (0.39, 0.9), (0.40, 0.79), (0.40, 0.80),
                                              (0.62, 1.0), (NAN, 0.0)]) for _ in range(5)]
    scn.moire = [pick(r, [0.1] * 5 + [None, 0.39, 0.4, 0.69, 0.7, 0.8]) for _ in range(5)]
    scn.ring = [pick(r, [0.1] * 6 + [None, 0.5, 0.75]) for _ in range(5)]


def _op_local(scn, r, user):
    t1 = pick(r, [None, 0.1, 0.29, 0.3, 0.5, 0.55, 0.72])
    t2 = pick(r, [None, 0.2, 0.41, 0.58])
    lu = pick(r, USERS[:8])
    scn.local = [(lu, t1, t2)] * 4 + [(pick(r, [lu, lu, lu, "u_1a2b"]), t1, t2)]
    scn.cache_age_h = pick(r, [1.0] * 3 + [None, 72.0, 73.0, 80.0])


def _op_flash(scn, r, user):
    scn.flash = None if r.random() < 0.1 else {
        "r": pick(r, [0.85] * 4 + [None, 0.1, 0.29, 0.3, 0.7, 0.75]), "amplitude": pick(r, [9.0] * 4 + [None, 2.0, 3.99, 4.0]),
        "lag_frames": pick(r, [1.0] * 4 + [None, -1.0, 0.0, 3.0, 4.0, 6.0]),
        "lag_std_frames": pick(r, [0.5] * 4 + [None, 1.0, 1.5]), "order_ok": pick(r, [True] * 4 + [None, False]),
        "skin_score": pick(r, [None, 0.1, 0.3, 0.9])}
    scn.flash_enabled = r.random() > 0.2


def _op_depth(scn, r, user):
    scn.depth_on(d0_valid_ratio=pick(r, [0.9, 0.5, 0.3, None]), d1_plane_rms_mm=pick(r, [9.0, 6.0, 2.0, None]),
                     d2_quad_rms_mm=pick(r, [6.0, 3.0, 1.0]), d3_nose_relief_mm=pick(r, [22.0, 10.0, 5.0]),
                     d4_ipd_mm=pick(r, [63.0, 30.0, None]), absolute=r.random() < 0.5,
                     m2_depth_step_mm=pick(r, [None, 5.0, 12.0]), m3_template_rms_mm=pick(r, [None, 6.5, 9.0]))


def _op_cloud(scn, r, user):
    if scn.mode == "ONLINE":
        scn.cloud = pick(r, [dict(B().cloud, top1_user=user)] * 2 + [
            None, {"ok": False}, {"ok": True, "top1_user": None, "top1_similarity": None},
            {"ok": True, "top1_user": user, "top1_similarity": pick(r, [79.0, 80.0, 92.0, 98.99, 99.0, 99.6]),
                 "runner_up_similarity": pick(r, [None, 79.0, 80.0, 85.0])}])


def _op_camera(scn, r, user):
    scn.label = pick(r, ["FaceTime HD Camera"] * 2 + ["", "OBS Virtual Camera", "Some Capture Device"])
    if r.random() < 0.3:
        scn.ts = [1000, 1033, 1033, 1099, 1132]


def _op_rng_rate(scn, r, user):
    scn.rng = StubRng(pick(r, [0.0, 0.05, 0.1499, 0.15, 0.2, 0.3, 0.99]))
    scn.rate_limit_retry_s = pick(r, [None, 0.0, 30.0])


def _op_cfg(scn, r, user):
    patch: dict = {}
    if r.random() < 0.15:
        patch.setdefault("offline", {})["auto_allow_max_risk"] = pick(r, ["low", "high"])
    if r.random() < 0.1:
        patch["schedule"] = {"high_risk_requires_stepup_online": False}
    if r.random() < 0.1:
        patch.setdefault("match", {})["rekognition"] = {"enabled": False}
    if r.random() < 0.1:
        patch.setdefault("liveness", {})["mask"] = {"spectral_enabled": True}
    if r.random() < 0.05:
        patch.setdefault("liveness", {})["flash"] = {"enabled": False}
    if patch:
        scn.cfg(patch)


_OPS = (_op_bundle, _op_refresh, _op_pad, _op_quality, _op_device_moire_ring, _op_local, _op_flash, _op_depth,
        _op_cloud, _op_camera, _op_rng_rate, _op_cfg)


@pytest.fixture(scope="module", params=list(PROFILES))
def corpus(request):
    r = random.Random(20261114)
    out = []
    for _ in range(N):
        scn = random_scn(r, PROFILES[request.param])
        signals, ctx, mode, now, T = scn.build()
        d = evaluate(signals, ctx, mode, now, cfg=T, rate_limit_retry_s=scn.rate_limit_retry_s, rng=scn.rng)
        out.append((scn, ctx, now, T, d))
    return out


def test_corpus_covers_every_outcome(corpus):
    seen = {(d.decision, d.mode) for *_, d in corpus}
    assert seen == {(a, m) for a in ("ALLOW", "STEP_UP", "DENY") for m in ("ONLINE", "OFFLINE")}


def test_P01_hard_spoof_evidence_is_always_deny(corpus):
    for *_, d in corpus:
        codes = set(d.reason_codes)
        if codes & (HARD_LIVENESS_CODES | {"INJECTION_VIRTUAL_CAMERA", "MASK_CUE_RIGID"}) or (
                d.bio_result == "BIO_FAIL" and codes & {"MASK_CUE_EDGE", "MASK_CUE_SHAPE", "MASK_CUE_SPECTRAL"}):
            assert d.decision == "DENY" and d.next_action.steps == ()  # no step-up session can upgrade it


def test_P02_codes_non_empty_and_in_closed_list(corpus):
    for *_, d in corpus:
        assert d.reason_codes and set(d.reason_codes) <= ALL_CODES


def test_P03_offline_allow_only_from_f1(corpus):
    for scn, ctx, now, T, d in corpus:
        if d.mode == "OFFLINE" and d.decision == "ALLOW":
            Toff = T.for_mode("OFFLINE")
            risk = zone_risk(ctx.lvb, d.zone)
            assert d.bio_result == "BIO_PASS" and d.schedule_result == "IN_WINDOW"
            assert cache_state(ctx.lvb, True, now, T.cache) == "FRESH" and d.cache_state == "FRESH"
            assert RISK_LEVELS[risk] <= RISK_LEVELS[Toff.offline.auto_allow_max_risk] and risk != "high"


def test_P04_unsure_step_ups_require_the_matching_steps(corpus):
    for *_, d in corpus:
        if d.bio_result == "BIO_UNSURE":
            assert d.decision != "ALLOW"
            if d.decision == "STEP_UP" and "RANDOM_CHALLENGE" not in d.reason_codes:
                steps = set(d.next_action.steps)
                assert ("CHALLENGE" in steps) == ("LIVENESS" in d.causes)
                if "MATCH" in d.causes or d.mode == "OFFLINE":
                    assert "SECOND_FACTOR" in steps


def test_P04_passing_only_the_challenge_never_allows_a_two_step_session():
    f = Flow(OB().set(pad=[0.85, 0.82, 0.60, 0.50, 0.70]))
    assert f.first.next_action.steps == ("CHALLENGE", "SECOND_FACTOR")
    assert f.challenge().decision == "STEP_UP"


def test_P05_schedule_deny_type_is_always_deny(corpus):
    for *_, d in corpus:
        if d.schedule_result in DENY_TYPE:
            assert d.decision == "DENY" and not d.next_action.steps


def _raise_pass_bars(scn: Scn, r: random.Random) -> Scn:
    """Raise one pass bar (keeping the offline override >= online, as the loader requires)."""
    T = scn.thresholds()
    which = pick(r, ["pad", "flash", "local", "margin", "rek", "luma", "d1", "strong_live"])
    up = scn.copy()
    if which == "pad":
        up.cfg({"liveness": {"pad": {"pass_min": T.liveness.pad.pass_min + 0.05}},
                "offline": {"overrides": {"liveness": {"pad": {"pass_min": T.for_mode("OFFLINE").liveness.pad.pass_min
                                                                + 0.05}}}}})
    elif which == "flash":
        up.cfg({"liveness": {"flash": {"pass_min_r": T.liveness.flash.pass_min_r + 0.1}},
                "offline": {"overrides": {"liveness": {"flash": {
                    "pass_min_r": T.for_mode("OFFLINE").liveness.flash.pass_min_r + 0.1}}}}})
    elif which == "local":
        up.cfg({"match": {"local": {"allow_min_cosine": T.match.local.allow_min_cosine + 0.1}},
                "offline": {"overrides": {"match": {"local": {
                    "allow_min_cosine": T.for_mode("OFFLINE").match.local.allow_min_cosine + 0.1}}}}})
    elif which == "margin":
        up.cfg({"match": {"local": {"min_margin_top1_top2": T.match.local.min_margin_top1_top2 + 0.1}},
                "offline": {"overrides": {"match": {"local": {
                    "min_margin_top1_top2": T.for_mode("OFFLINE").match.local.min_margin_top1_top2 + 0.1}}}}})
    elif which == "rek":
        up.cfg({"match": {"rekognition": {"allow_min_similarity": 99.7}}})
    elif which == "luma":
        up.cfg({"quality": {"min_luma_mean": 130}})
    elif which == "d1":
        up.cfg({"liveness": {"depth": {"d1_plane_rms_pass_mm": 10.0}}})
    else:
        up.cfg({"liveness": {"pad": {"strong_live": 0.97}}})
    return up


def test_P06_raising_a_pass_threshold_never_creates_an_allow(corpus):
    r = random.Random(6)
    for scn, *_, d in corpus[:600]:
        if d.decision == "ALLOW":
            continue
        up = _raise_pass_bars(scn, r)
        up.rng = StubRng(scn.rng.value)
        assert up.evaluate().decision != "ALLOW", (scn, d.reason_codes)


def test_P07_offline_never_less_restrictive_without_cloud_evidence(corpus):
    """Lead R9: compared on inputs without cloud evidence (Rekognition disabled online)."""
    for scn, *_ in corpus[:800]:
        on = scn.copy().set(mode="ONLINE", cloud=None).cfg({"match": {"rekognition": {"enabled": False}}})
        off = scn.copy().set(mode="OFFLINE", cloud=None).cfg({"match": {"rekognition": {"enabled": False}}})
        on.rng, off.rng = StubRng(scn.rng.value), StubRng(scn.rng.value)
        d_on, d_off = on.evaluate(), off.evaluate()
        assert DECISION_RANK[d_off.decision] >= DECISION_RANK[d_on.decision], (d_on.reason_codes, d_off.reason_codes)


def test_P08_engine_never_raises_on_garbage(corpus):
    from edge.policy.signals import AttemptSignals

    r = random.Random(8)
    scn, ctx, now, T, _ = corpus[0]
    good = scn.signals()
    for _ in range(300):
        junk = AttemptSignals.model_construct(**{
            **dict(good),
            pick(r, ["frames", "camera", "flash", "depth", "cloud_match", "t0", "recapture_count",
                     "template_cache_age_h"]): pick(r, [None, "x", 42, [], {}, object(), -1, NAN])})
        d = evaluate(junk, ctx, "ONLINE", now, cfg=T)
        assert d.decision in ("DENY", "STEP_UP", "ALLOW") and d.reason_codes
        if d.decision == "ALLOW":
            assert d.detail is None  # only a fully valid evaluation may allow


@pytest.mark.parametrize("stage", ["liveness_fusion", "identity_match", "quality_gate", "injection_check",
                                   "evaluate_schedule", "combine", "cache_state"])
def test_P08_injected_stage_exception_is_system_error(monkeypatch, stage):
    def boom(*a, **k):
        raise RuntimeError(f"{stage} exploded")

    monkeypatch.setattr(engine, stage, boom)
    d = B().evaluate()
    assert d.decision == "DENY" and "SYSTEM_ERROR" in d.reason_codes and d.next_action.type == "CONTACT_DESK"


def test_P08_online_clock_rollback_is_offline_staff_override_never_combine_without_schedule():
    """Lead 2026-11-14: wall (demo) clock before LVB issued_at - 300 s while online -> online_bundle_ok() is
    false -> OFFLINE -> cache INVALID -> staff override only. combine() never sees (ONLINE, INVALID)."""
    d = B().fixed().who("u_3c4d", "LIB", "2026-11-14T07:50").evaluate()  # fixed issued_at = 08:00 IST
    assert d.mode == "OFFLINE" and d.decision == "STEP_UP" and d.detail is None
    assert {"SCHEDULE_BUNDLE_INVALID", "OFFLINE_FALLBACK_REQUIRED", "OFFLINE_MODE"} <= set(d.reason_codes)
    assert list(d.next_action.steps) == ["SECOND_FACTOR"] and list(d.next_action.methods) == ["STAFF_OVERRIDE"]
    assert d.schedule_result is None


def test_P08_combine_raise_for_a_skipped_schedule_is_deny_system_error(monkeypatch):
    """If (ONLINE, cache INVALID, schedule skipped) ever reached combine() it raises; evaluate() turns that into
    DENY SYSTEM_ERROR (CONTACT_DESK), never an exception."""
    T = B().thresholds().for_mode("ONLINE")
    with pytest.raises(ValueError, match="unknown schedule result"):
        engine.combine("BIO_PASS", [], set(), None, "INVALID", "low", "ONLINE", T)
    monkeypatch.setattr(engine, "online_bundle_ok", lambda *a, **k: True)  # force the impossible state
    d = B().fixed().who("u_3c4d", "LIB", "2026-11-14T07:50").evaluate()
    assert d.decision == "DENY" and d.reason_codes == ("SYSTEM_ERROR",) and d.next_action.type == "CONTACT_DESK"


def test_P08_invalid_mode_and_naive_clock_are_system_error():
    s, ctx, _mode, now, T = B().build()
    assert evaluate(s, ctx, "HALF_ONLINE", now, cfg=T).reason_codes[0] == "SYSTEM_ERROR"
    assert evaluate(s, ctx, "ONLINE", now.replace(tzinfo=None), cfg=T).reason_codes[0] == "SYSTEM_ERROR"
    bad = s.model_copy(update={"camera": CameraMeta.model_construct(camera_label=None, frame_timestamps_ms=None)})
    assert evaluate(bad, ctx, "ONLINE", now, cfg=T).decision == "DENY"


def test_P09_random_challenge_only_tightens(corpus):
    for scn, *_ in corpus:
        lo, hi = scn.copy(), scn.copy()
        lo.rng, hi.rng = StubRng(0.0), StubRng(0.99)
        d_lo, d_hi = lo.evaluate(), hi.evaluate()
        assert d_lo.rng_draws <= 1 and d_hi.rng_draws <= 1
        if d_hi.decision == "ALLOW":
            T = scn.thresholds().for_mode(d_hi.mode)
            if T.challenge.random_rate > 0:
                assert d_lo.decision == "STEP_UP"
                assert set(d_lo.reason_codes) == {"RANDOM_CHALLENGE"} | ({"OFFLINE_MODE"} if d_lo.mode == "OFFLINE"
                                                                         else set())
                assert list(d_lo.next_action.steps) == ["CHALLENGE"]
        else:
            assert d_lo.decision == d_hi.decision and d_lo.reason_codes == d_hi.reason_codes
            assert d_hi.rng_draws == 0


def test_P11_allow_without_user_only_after_manual_review(corpus):
    for *_, d in corpus:
        if d.decision == "ALLOW":
            assert d.user_id is not None  # initial ALLOWs always have a candidate
    f = Flow(B().set(luma=[40.0] * 5, recapture_count=2))
    d = f.fallback(method="STAFF_OVERRIDE", code="48213907")
    assert d.decision == "ALLOW" and d.user_id is None and "FALLBACK_OK" in d.reason_codes
    assert d.fallback["method"] == "STAFF_OVERRIDE" and d.fallback["staff_id"] == "s_guard01"


def test_P12_no_auto_allow_on_the_non_flash_path(corpus):
    for scn, _ctx, _now, T, d in corpus:
        if not scn.flash_enabled or not T.liveness.flash.enabled:
            assert d.decision != "ALLOW"
            if d.decision == "STEP_UP" and d.bio_result == "BIO_UNSURE":
                assert "CHALLENGE" in d.next_action.steps


def test_P13_online_only_with_a_verified_fresh_recently_refreshed_bundle(corpus):
    for _scn, ctx, now, T, d in corpus:
        if d.mode == "ONLINE":
            assert ctx.lvb is not None and cache_state(ctx.lvb, True, now, T.cache) == "FRESH"
            assert ctx.refresh_age_s is not None and ctx.refresh_age_s <= 30 * 60
