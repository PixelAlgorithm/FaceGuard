"""docs/POLICY_TEST_CASES.md (policy 2026-11-14.2): every initial-decision row through the pure engine.

Step-up continuations (Q13/Q14/Q17/Q21, L21, C02-C10, RC04-RC07/RC09, S02/S03/S14/S45-S49, O05-O10,
O12, O15, O20/O21, O29, O44-O47) live in test_stepup.py; RL* in test_ratelimit.py; X/D/Y in edge/offline.
Assertions per the doc: decision exact; reason_codes an exact SET; steps exact; methods exact set when
listed; next_action.type when listed. Rows superseded by a lead round-2 decision keep the doc
expectation as a strict xfail (reason names the decision) next to a positive test of the lead rule.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest

from edge.policy.tests.builders import (
    L03_PAD,
    O14_PAD,
    OB,
    PHONE,
    B,
    Scn,
    base_thresholds,
    bundle_signed_at,
    load_example_bundle,
    tampered,
    utc,
)

# Flash bars come from config/thresholds.yaml (lead calibration 2026-11-14: lag window 0-8 frames,
# lag std <= 1.5, min amplitude 2.0). Doc rows L08/L10-L12 pinned the old bars (lag 6 / amplitude 2.0);
# they now use "just outside the configured window" / "just below the configured amplitude".
_F = base_thresholds().liveness.flash
LAG_OUT = float(_F.lag_max_frames) + 1  # doc L08: 6 (old window 0-3)
WEAK_AMP = float(_F.min_amplitude) - 0.5  # doc L10-L12: 2.0 (old bar 4.0)

ON = {"TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"}
ONH = {"TOTP", "CARD", "EMAIL_OTP"}
OFF = {"TOTP", "CARD", "STAFF_OVERRIDE"}
OFFH = {"TOTP", "STAFF_OVERRIDE"}
STF = {"STAFF_OVERRIDE"}
OM, OFR = "OFFLINE_MODE", "OFFLINE_FALLBACK_REQUIRED"
EXP, INV, HR = "SCHEDULE_EXPIRED_CACHE", "SCHEDULE_BUNDLE_INVALID", "OFFLINE_HIGH_RISK_ZONE"


@dataclass(frozen=True)
class Case:
    id: str
    row: str  # DECISION_POLICY matrix row
    build: Callable[[], Scn]
    decision: str
    codes: set[str]
    steps: list[str] | None = None
    methods: set[str] | None = None
    type: str | None = None
    attempts_left_doc: int | None = None  # doc value ("retries_after" = default semantics, lead final)
    mode: str | None = None
    rng_calls: int | None = None


def tampered_now() -> dict:
    return tampered(bundle_signed_at(B().t0))


CASES = [
    # ---------------------------------------------------------------- §1 quality, injection, pre-checks
    Case("Q01", "N1", B, "ALLOW", {"ACCESS_OK"}, steps=[], type="OPEN_DOOR"),
    Case("Q02", "A2", lambda: B().set(luma=[40.0] * 5), "STEP_UP", {"QUALITY_LOW_LIGHT"}, type="RECAPTURE"),
    Case("Q03", "A2", lambda: B().set(lapvar=[30.0] * 5), "STEP_UP", {"QUALITY_BLUR"}, type="RECAPTURE"),
    Case("Q04", "A2", lambda: B().set(secondary=[0.0, 0.7, 0.0, 0.0, 0.0]), "STEP_UP", {"MULTIPLE_FACES"},
         type="RECAPTURE"),
    Case("Q05", "A3", lambda: B().set(luma=[40.0] * 5, recapture_count=2), "STEP_UP", {"QUALITY_LOW_LIGHT"},
         steps=["SECOND_FACTOR"], methods=STF, type="SECOND_FACTOR", attempts_left_doc=1),
    Case("Q06", "N1", lambda: B().set(lapvar=[150.0, 150.0, 150.0, 30.0, 30.0]), "ALLOW", {"ACCESS_OK"},
         type="OPEN_DOOR"),
    Case("Q07", "A2", lambda: B().set(yaw=[35.0, 35.0, 35.0, 5.0, 5.0]), "STEP_UP", {"QUALITY_POSE"},
         type="RECAPTURE"),
    Case("Q08", "A4", lambda: B().set(label="OBS Virtual Camera"), "DENY", {"INJECTION_VIRTUAL_CAMERA"},
         type="NONE"),
    Case("Q09", "N9", lambda: B().set(label=""), "STEP_UP", {"LIVENESS_UNSURE"}, steps=["CHALLENGE"],
         type="CHALLENGE"),
    Case("Q12", "A2", lambda: OB().set(luma=[40.0] * 5), "STEP_UP", {"QUALITY_LOW_LIGHT", OM}, type="RECAPTURE"),
    Case("Q15", "A6", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:05").set(luma=[40.0] * 5, recapture_count=2),
         "DENY", {"QUALITY_LOW_LIGHT"}, type="CONTACT_DESK"),
    Case("Q16", "A3", lambda: OB().set(luma=[40.0] * 5, recapture_count=2), "STEP_UP",
         {"QUALITY_LOW_LIGHT", OM, OFR}, steps=["SECOND_FACTOR"], methods=STF, attempts_left_doc=1),
    Case("Q18", "A6", lambda: OB().who("u_3c4d", "LAB", "2026-11-14T10:05").cfg(
        {"offline": {"auto_allow_max_risk": "low"}}).set(luma=[40.0] * 5, recapture_count=2), "DENY",
         {"QUALITY_LOW_LIGHT", OM}, type="CONTACT_DESK"),
    Case("Q19", "A4", lambda: B().set(luma=[40.0] * 5, recapture_count=2, label="OBS Virtual Camera"), "DENY",
         {"INJECTION_VIRTUAL_CAMERA"}, type="NONE"),
    Case("Q20", "A6", lambda: OB().who("u_7a8b", "SRV", "2026-11-14T10:05").set(luma=[40.0] * 5, recapture_count=2),
         "DENY", {"QUALITY_LOW_LIGHT", OM}, type="CONTACT_DESK"),
    Case("Q22", "A2", lambda: B().set(luma=[40.0] * 5, recapture_count=1), "STEP_UP", {"QUALITY_LOW_LIGHT"},
         type="RECAPTURE"),
    # ---------------------------------------------------------------- §2 liveness fusion
    Case("L01", "N12", lambda: B().set(pad=[0.10, 0.20, 0.15, 0.90, 0.25]), "DENY", {"SPOOF_PASSIVE"}, type="NONE"),
    Case("L02", "N1", lambda: B().set(pad=[0.85, 0.82, 0.60, 0.50, 0.81]), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("L03", "N9", lambda: B().set(pad=list(L03_PAD)), "STEP_UP", {"LIVENESS_UNSURE"}, steps=["CHALLENGE"]),
    Case("L05", "N12", lambda: B().set(device=PHONE), "DENY", {"SPOOF_DEVICE_DETECTED"}, type="NONE"),
    Case("L06", "N9", lambda: B().set(device=[(0.30, 0.5)] * 5), "STEP_UP", {"LIVENESS_UNSURE"}, steps=["CHALLENGE"]),
    Case("L07", "N12", lambda: B().set(flash=dict(B().flash, r=0.12, amplitude=9.0)), "DENY",
         {"SPOOF_FLASH_MISMATCH"}, type="NONE"),
    Case("L08", "N12", lambda: B().set(flash=dict(B().flash, r=0.85, lag_frames=LAG_OUT)), "DENY",
         {"SPOOF_FLASH_MISMATCH"}, type="NONE"),
    Case("L09", "N9", lambda: B().set(flash=dict(B().flash, r=0.50)), "STEP_UP", {"LIVENESS_UNSURE"},
         steps=["CHALLENGE"]),
    Case("L10", "N1", lambda: B().set(flash=dict(B().flash, amplitude=WEAK_AMP, r=0.10)), "ALLOW", {"ACCESS_OK"},
         type="OPEN_DOOR"),
    Case("L11", "N9", lambda: B().set(flash=dict(B().flash, amplitude=WEAK_AMP, r=0.10),
                                      pad=[0.85, 0.84, 0.83, 0.86, 0.82]), "STEP_UP", {"LIVENESS_UNSURE"},
         steps=["CHALLENGE"]),
    Case("L12", "F5", lambda: OB().set(flash=dict(B().flash, amplitude=WEAK_AMP)), "STEP_UP",
         {"LIVENESS_UNSURE", OM, OFR}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFF),
    # lead calibration vectors (operator webcam, n=3 genuine): lag 7 PASS, lag 9 FAIL, amp 2.5 PASS, amp 1.5 WEAK
    Case("LCAL1", "N1", lambda: B().set(flash=dict(B().flash, r=0.9, lag_frames=7.0, lag_std_frames=1.05)), "ALLOW",
         {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("LCAL2", "N12", lambda: B().set(flash=dict(B().flash, r=0.9, lag_frames=9.0)), "DENY",
         {"SPOOF_FLASH_MISMATCH"}, type="NONE"),
    Case("LCAL3", "N1", lambda: B().set(flash=dict(B().flash, r=0.9, amplitude=2.5)), "ALLOW", {"ACCESS_OK"},
         type="OPEN_DOOR"),
    Case("LCAL4", "N1", lambda: B().set(flash=dict(B().flash, r=0.9, amplitude=1.5)), "ALLOW", {"ACCESS_OK"},
         type="OPEN_DOOR"),  # WEAK -> online ambient exception (PAD mean 0.94, clean device, moire 0.10)
    Case("LCAL4O", "F5", lambda: OB().set(flash=dict(B().flash, r=0.9, amplitude=1.5)), "STEP_UP",
         {"LIVENESS_UNSURE", OM, OFR}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFF),  # no exception offline
    Case("L13", "N9", lambda: B().set(moire=[0.80] * 5), "STEP_UP", {"LIVENESS_UNSURE"}, steps=["CHALLENGE"]),
    Case("L14", "N12", lambda: B().set(moire=[0.80] * 5, flash=dict(B().flash, r=0.50)), "DENY", {"SPOOF_MOIRE"},
         type="NONE"),
    Case("L15", "N12", lambda: B().set(device=PHONE, flash=dict(B().flash, r=0.12)), "DENY",
         {"SPOOF_DEVICE_DETECTED", "SPOOF_FLASH_MISMATCH"}, type="NONE"),
    Case("L16", "N12", lambda: B().depth_on(d1_plane_rms_mm=1.8, d2_quad_rms_mm=None, d3_nose_relief_mm=None,
                                            d4_ipd_mm=None), "DENY", {"SPOOF_FLAT_DEPTH"}, type="NONE"),
    Case("L17", "A2", lambda: B().depth_on(d0_valid_ratio=0.30), "STEP_UP", {"QUALITY_DEPTH_INVALID"},
         type="RECAPTURE"),
    Case("L18", "N12", lambda: B().depth_on(d4_ipd_mm=30.0, absolute=True), "DENY", {"SPOOF_DEPTH_SCALE"},
         type="NONE"),
    Case("L19", "N1", lambda: B().depth_on(), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("L20", "N15", lambda: B().set(flash_enabled=False), "STEP_UP", {"LIVENESS_UNSURE"}, steps=["CHALLENGE"],
         rng_calls=0),
    Case("L22", "F10", lambda: OB().set(flash_enabled=False), "STEP_UP", {"LIVENESS_UNSURE", OM, OFR},
         steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFF),
    Case("L23", "N12", lambda: B().set(flash_enabled=False, moire=[0.80] * 5), "DENY", {"SPOOF_MOIRE"}, type="NONE"),
    Case("L24", "N10", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:00").set(flash_enabled=False), "STEP_UP",
         {"LIVENESS_UNSURE", "SCHEDULE_HIGH_RISK_ZONE"}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=ONH),
    Case("L25", "N15", lambda: B().cfg({"liveness": {"flash": {"enabled": False}}}), "STEP_UP", {"LIVENESS_UNSURE"},
         steps=["CHALLENGE"]),
    # ---------------------------------------------------------------- §3 mask cues
    Case("M01", "N9", lambda: B().set(ring=[0.60] * 5), "STEP_UP", {"MASK_CUE_EDGE"}, steps=["CHALLENGE"]),
    Case("M02", "N12", lambda: B().depth_on(m2_depth_step_mm=12.0, m3_template_rms_mm=9.0), "DENY",
         {"MASK_CUE_EDGE", "MASK_CUE_SHAPE"}, type="NONE"),
    Case("M03", "N9", lambda: B().set(ring=[0.80] * 5), "STEP_UP", {"MASK_CUE_EDGE"}, steps=["CHALLENGE"]),
    Case("M04", "N9", lambda: B().depth_on(m3_template_rms_mm=6.5).set(ring=[0.55] * 5), "STEP_UP",
         {"MASK_CUE_EDGE", "MASK_CUE_SHAPE"}, steps=["CHALLENGE"]),
    # ---------------------------------------------------------------- §3a random deformation challenge
    Case("RC01", "N14", lambda: B().r(0.05), "STEP_UP", {"RANDOM_CHALLENGE"}, steps=["CHALLENGE"], type="CHALLENGE",
         attempts_left_doc=1),
    Case("RC02", "N1", lambda: B().r(0.15), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR", rng_calls=1),
    Case("RC03", "N14", lambda: B().r(0.1499), "STEP_UP", {"RANDOM_CHALLENGE"}, steps=["CHALLENGE"]),
    Case("RC07", "N14", lambda: B().depth_on().r(0.05), "STEP_UP", {"RANDOM_CHALLENGE"}, steps=["CHALLENGE"]),
    Case("RC08", "F9", lambda: OB().r(0.20), "STEP_UP", {"RANDOM_CHALLENGE", OM}, steps=["CHALLENGE"]),
    Case("RC10", "N1", lambda: B().r(0.20), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("RC11", "F1", lambda: OB().r(0.30), "ALLOW", {"ACCESS_OK", OM}, type="OPEN_DOOR"),
    Case("RC12", "N3", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:50").r(0.05), "STEP_UP",
         {"SCHEDULE_GRACE_WINDOW"}, steps=["SECOND_FACTOR"], methods=ON, rng_calls=0),
    Case("RC13", "N9", lambda: B().set(pad=list(L03_PAD)).r(0.05), "STEP_UP", {"LIVENESS_UNSURE"},
         steps=["CHALLENGE"], rng_calls=0),
    Case("RC14", "N12", lambda: B().set(device=PHONE).r(0.05), "DENY", {"SPOOF_DEVICE_DETECTED"}, type="NONE",
         rng_calls=0),
    Case("RC15", "N1", lambda: B().cfg({"challenge": {"random_rate": 0}}).r(0.0), "ALLOW", {"ACCESS_OK"},
         type="OPEN_DOOR"),
    Case("RC16", "N14", lambda: B().cfg({"challenge": {"random_rate": 1.0},
                                         "offline": {"overrides": {"challenge": {"random_rate": 1.0}}}}).r(0.99),
         "STEP_UP", {"RANDOM_CHALLENGE"}, steps=["CHALLENGE"]),
    Case("RC17", "N1", B, "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR", rng_calls=1),
    # ---------------------------------------------------------------- §4 identity
    Case("I01", "N9", lambda: B().set(cloud=dict(B().cloud, top1_similarity=92.0)), "STEP_UP", {"MATCH_LOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("I02", "N9", lambda: B().set(cloud=dict(B().cloud, top1_similarity=99.5, runner_up_similarity=85.0)),
         "STEP_UP", {"MATCH_AMBIGUOUS"}, steps=["SECOND_FACTOR"], methods=ON),
    Case("I03", "N13", lambda: B().set(cloud={"ok": True, "top1_user": None, "top1_similarity": None},
                                       local=[("u_3c4d", 0.22, 0.15)] * 5), "DENY", {"NOT_ENROLLED"},
         type="CONTACT_DESK"),
    Case("I04", "N9", lambda: B().set(local=[("u_1a2b", 0.61, 0.40)] * 5), "STEP_UP", {"MATCH_AMBIGUOUS"},
         steps=["SECOND_FACTOR"]),
    Case("I05", "N9", lambda: B().set(local=[("u_3c4d", 0.72, 0.41)] * 4 + [("u_1a2b", 0.45, 0.40)]), "STEP_UP",
         {"MATCH_AMBIGUOUS"}, steps=["SECOND_FACTOR"]),
    Case("I06", "N9", lambda: B().set(pad=list(L03_PAD), cloud=dict(B().cloud, top1_similarity=92.0)), "STEP_UP",
         {"LIVENESS_UNSURE", "MATCH_LOW"}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=ON),
    Case("I07", "F1", lambda: B().set(cloud={"ok": False}), "ALLOW", {"ACCESS_OK", OM}, type="OPEN_DOOR",
         mode="OFFLINE"),
    Case("I08", "F5", lambda: OB().set(local=[("u_3c4d", 0.53, 0.30)] * 5), "STEP_UP", {"MATCH_LOW", OM, OFR},
         steps=["SECOND_FACTOR"], methods=OFF),
    Case("I09", "F5", lambda: OB().set(local=[("u_3c4d", 0.70, 0.58)] * 5), "STEP_UP", {"MATCH_AMBIGUOUS", OM, OFR},
         steps=["SECOND_FACTOR"], methods=OFF),
    Case("I10", "F8", lambda: OB().set(local=[("u_1a2b", 0.18, 0.12)] * 5), "DENY", {"NOT_ENROLLED", OM},
         type="CONTACT_DESK"),
    Case("I11", "N12", lambda: B().set(device=PHONE, cloud={"ok": True, "top1_user": None, "top1_similarity": None}),
         "DENY", {"SPOOF_DEVICE_DETECTED", "NOT_ENROLLED"}, type="NONE"),
    Case("I12", "N1", lambda: B().cfg({"match": {"rekognition": {"enabled": False}}}).set(cloud=None), "ALLOW",
         {"ACCESS_OK"}, type="OPEN_DOOR", mode="ONLINE"),
    Case("I13", "N9", lambda: B().cfg({"match": {"rekognition": {"enabled": False}}}).set(
        cloud=None, local=[("u_3c4d", 0.53, 0.30)] * 5), "STEP_UP", {"MATCH_LOW"}, steps=["SECOND_FACTOR"],
         methods=ON, mode="ONLINE"),
    Case("I14", "F1", lambda: B().set(cloud={"ok": False, "top1_user": None}), "ALLOW", {"ACCESS_OK", OM},
         type="OPEN_DOOR", mode="OFFLINE"),
    # ---------------------------------------------------------------- §5 schedule (SC1)
    Case("S01", "N3", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:50"), "STEP_UP", {"SCHEDULE_GRACE_WINDOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("S04", "N4", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:40"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S05", "N1", lambda: B().who("u_3c4d", "LAB", "2026-11-14T20:30"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S06", "N4", lambda: B().who("u_3c4d", "LAB", "2026-11-15T11:00"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S07", "N4", lambda: B().who("u_3c4d", "LAB", "2026-11-16T10:00"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S08", "N1", lambda: B().who("u_3c4d", "LIB", "2026-11-18T23:30"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S09", "N6", lambda: B().who("u_3c4d", "HOSTEL", "2026-11-14T21:00"), "DENY",
         {"SCHEDULE_ZONE_NOT_PERMITTED"}, type="CONTACT_DESK"),
    Case("S10", "N3", lambda: B().who("u_1a2b", "HOSTEL", "2026-11-14T23:10"), "STEP_UP", {"SCHEDULE_GRACE_WINDOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("S11", "N4", lambda: B().who("u_1a2b", "HOSTEL", "2026-11-14T23:20"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S12", "N4", lambda: B().who("u_1a2b", "HOSTEL", "2026-11-15T00:30"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S13", "N2", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:00"), "STEP_UP", {"SCHEDULE_HIGH_RISK_ZONE"},
         steps=["SECOND_FACTOR"], methods=ONH),
    Case("S15", "N4", lambda: B().who("u_7a8b", "SRV", "2026-11-14T08:55"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S16", "N6", lambda: B().who("u_5e6f", "SRV", "2026-11-16T11:00"), "DENY", {"SCHEDULE_ZONE_NOT_PERMITTED"},
         type="CONTACT_DESK"),
    Case("S17", "N8", lambda: B().who("u_a3b4", "MAIN", "2026-11-14T09:00"), "DENY", {"SCHEDULE_REVOKED"},
         type="CONTACT_DESK"),
    Case("S18", "N1", lambda: B().who("u_e1f2", "LAB", "2026-11-14T15:00"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S19", "N5", lambda: B().who("u_e1f2", "LAB", "2026-11-14T18:10"), "DENY", {"SCHEDULE_NO_ENTITLEMENT"},
         type="CONTACT_DESK"),
    Case("S20", "N6", lambda: B().who("u_e1f2", "LIB", "2026-11-14T11:00"), "DENY", {"SCHEDULE_ZONE_NOT_PERMITTED"},
         type="CONTACT_DESK"),
    Case("S21", "N7", lambda: B().who("u_9c0d", "LAB", "2026-11-20T10:00"), "DENY", {"SCHEDULE_HOLIDAY"}, type="NONE"),
    Case("S22", "N1", lambda: B().who("u_7a8b", "LAB", "2026-11-20T10:00"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S23", "N5", lambda: B().who("u_9c0d", "LAB", "2026-12-01T10:00"), "DENY", {"SCHEDULE_NO_ENTITLEMENT"},
         type="CONTACT_DESK"),
    Case("S24", "N1", lambda: B().who("u_c5d6", "LIB", "2026-11-15T08:00"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S25", "N4", lambda: B().who("u_7a8b", "LIB", "2026-11-15T08:00"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S26", "N6", lambda: B().who("u_c5d6", "LAB", "2026-11-16T10:00"), "DENY", {"SCHEDULE_ZONE_NOT_PERMITTED"},
         type="CONTACT_DESK"),
    Case("S27", "N5", lambda: B().set(cloud=dict(B().cloud, top1_user="u_zz99", top1_similarity=99.7),
                                      local=[("u_1a2b", 0.25, 0.20)] * 5), "DENY", {"SCHEDULE_NO_ENTITLEMENT"},
         type="CONTACT_DESK"),
    Case("S28", "N11", lambda: B().who("u_3c4d", "LAB", "2026-11-15T11:00").set(pad=list(L03_PAD)), "DENY",
         {"LIVENESS_UNSURE", "SCHEDULE_OUTSIDE_WINDOW"}, type="CONTACT_DESK"),
    Case("S29", "N11", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:50").set(pad=list(L03_PAD)), "DENY",
         {"LIVENESS_UNSURE", "SCHEDULE_GRACE_WINDOW"}, type="CONTACT_DESK"),
    Case("S30", "N12", lambda: B().who("u_a3b4", "LIB", "2026-11-14T10:05").set(device=PHONE), "DENY",
         {"SPOOF_DEVICE_DETECTED"}, type="NONE"),
    Case("S31", "N10", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:00").set(pad=list(L03_PAD)), "STEP_UP",
         {"LIVENESS_UNSURE", "SCHEDULE_HIGH_RISK_ZONE"}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=ONH),
    Case("S32", "N1", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:00").cfg(
        {"schedule": {"high_risk_requires_stepup_online": False}}), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S33", "N1", lambda: B().who("u_3c4d", "LIB", "2026-11-14T08:00"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S34", "N3", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:45"), "STEP_UP", {"SCHEDULE_GRACE_WINDOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("S35", "N4", lambda: B().who("u_3c4d", "LIB", "2026-11-14T07:44"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S36", "N1", lambda: B().who("u_3c4d", "LIB", "2026-11-14T20:59"), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR"),
    Case("S37", "N3", lambda: B().who("u_3c4d", "LIB", "2026-11-14T21:00"), "STEP_UP", {"SCHEDULE_GRACE_WINDOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("S38", "N3", lambda: B().who("u_3c4d", "LIB", "2026-11-14T21:14"), "STEP_UP", {"SCHEDULE_GRACE_WINDOW"},
         steps=["SECOND_FACTOR"], methods=ON),
    Case("S39", "N4", lambda: B().who("u_3c4d", "LIB", "2026-11-14T21:15"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S40", "N4", lambda: B().who("u_3c4d", "LIB", "2026-11-14T21:16"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S41", "N2", lambda: B().who("u_7a8b", "SRV", "2026-11-14T09:00"), "STEP_UP", {"SCHEDULE_HIGH_RISK_ZONE"},
         steps=["SECOND_FACTOR"], methods=ONH),
    Case("S42", "N4", lambda: B().who("u_7a8b", "SRV", "2026-11-14T08:59"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    Case("S43", "N2", lambda: B().who("u_7a8b", "SRV", "2026-11-14T20:59"), "STEP_UP", {"SCHEDULE_HIGH_RISK_ZONE"},
         steps=["SECOND_FACTOR"], methods=ONH),
    Case("S44", "N4", lambda: B().who("u_7a8b", "SRV", "2026-11-14T21:00"), "DENY", {"SCHEDULE_OUTSIDE_WINDOW"},
         type="NONE"),
    # ---------------------------------------------------------------- §6 offline (SC2)
    Case("O01", "F1", OB, "ALLOW", {"ACCESS_OK", OM}, type="OPEN_DOOR"),
    Case("O02", "F1", lambda: OB().who("u_3c4d", "LAB", "2026-11-14T11:00"), "ALLOW", {"ACCESS_OK", OM},
         type="OPEN_DOOR"),
    Case("O03", "F2", lambda: OB().who("u_3c4d", "LAB", "2026-11-14T11:00").cfg(
        {"offline": {"auto_allow_max_risk": "low"}}), "STEP_UP", {OM, HR, OFR}, steps=["SECOND_FACTOR"], methods=OFFH),
    Case("O04", "F2", lambda: OB().who("u_7a8b", "SRV", "2026-11-14T10:00"), "STEP_UP", {OM, HR, OFR},
         steps=["SECOND_FACTOR"], methods=OFFH),
    Case("O11", "F3", lambda: OB().who("u_3c4d", "LIB", "2026-11-14T07:50"), "STEP_UP",
         {"SCHEDULE_GRACE_WINDOW", OM, OFR}, steps=["SECOND_FACTOR"], methods=OFF),
    Case("O13", "F5", lambda: OB().set(pad=list(L03_PAD)), "STEP_UP", {"LIVENESS_UNSURE", OM, OFR},
         steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFF),
    Case("O14", "F5", lambda: OB().set(pad=list(O14_PAD)), "STEP_UP", {"LIVENESS_UNSURE", OM, OFR},
         steps=["CHALLENGE", "SECOND_FACTOR"]),
    Case("O16", "F7", lambda: OB().who("u_3c4d", "LIB", "2026-11-14T07:50").set(pad=list(L03_PAD)), "DENY",
         {"LIVENESS_UNSURE", "SCHEDULE_GRACE_WINDOW", OM}, type="CONTACT_DESK"),
    Case("O17", "F8", lambda: OB().set(device=PHONE), "DENY", {"SPOOF_DEVICE_DETECTED", OM}, type="NONE"),
    Case("O18", "F4", lambda: OB().who("u_a3b4", "MAIN", "2026-11-14T09:00"), "DENY", {"SCHEDULE_REVOKED", OM},
         type="CONTACT_DESK"),
    Case("O19", "E1", lambda: OB().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00"), "STEP_UP", {EXP, OM, OFR},
         steps=["SECOND_FACTOR"], methods=STF),
    Case("O22", "E2", lambda: OB().fixed().who("u_a3b4", "MAIN", "2026-11-14T21:00"), "DENY",
         {"SCHEDULE_REVOKED", EXP, OM}, type="CONTACT_DESK"),
    Case("O23", "E1", lambda: OB().fixed().who("u_7a8b", "SRV", "2026-11-14T20:45"), "STEP_UP", {EXP, OM, HR, OFR},
         methods=STF),
    Case("O26", "I1b", lambda: OB().fixed().set(t0=utc("2026-11-13T20:00:00"), now=utc("2026-11-13T20:00:00")),
         "STEP_UP", {INV, OM, OFR}, methods=STF),
    Case("O27", "I3", lambda: OB().set(bundle=tampered_now(), device=PHONE), "DENY", {"SPOOF_DEVICE_DETECTED", OM},
         type="NONE"),
    Case("O28", "F8", lambda: OB().set(cache_age_h=80.0), "DENY", {"NOT_ENROLLED", OM}, type="CONTACT_DESK"),
    Case("O30", "MO2", lambda: B().set(refresh_age_s=31 * 60), "ALLOW", {"ACCESS_OK", OM}, type="OPEN_DOOR",
         mode="OFFLINE"),
    Case("O31", "MO1", lambda: B().set(refresh_age_s=30 * 60), "ALLOW", {"ACCESS_OK"}, type="OPEN_DOOR",
         mode="ONLINE"),
    Case("O32", "MO2", lambda: B().who("u_7a8b", "SRV", "2026-11-14T10:00").set(refresh_age_s=45 * 60), "STEP_UP",
         {OM, HR, OFR}, steps=["SECOND_FACTOR"], methods=OFFH),
    Case("O33", "MO2", lambda: B().set(refresh_age_s=45 * 60, pad=list(O14_PAD)), "STEP_UP",
         {"LIVENESS_UNSURE", OM, OFR}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFF),
    Case("O35", "MO3", lambda: B().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00"), "STEP_UP", {EXP, OM, OFR},
         steps=["SECOND_FACTOR"], methods=STF, mode="OFFLINE"),
    Case("O36", "MO2", lambda: B().set(refresh_age_s=31 * 60).r(0.20), "STEP_UP", {"RANDOM_CHALLENGE", OM},
         steps=["CHALLENGE"]),
    Case("O37", "F6", lambda: OB().who("u_7a8b", "SRV", "2026-11-14T10:00").set(pad=list(L03_PAD)), "STEP_UP",
         {"LIVENESS_UNSURE", OM, HR, OFR}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=OFFH),
    Case("O38", "E3", lambda: OB().fixed().who("u_3c4d", "MAIN", "2026-11-14T21:00").set(pad=list(L03_PAD)),
         "STEP_UP", {"LIVENESS_UNSURE", EXP, OM, OFR}, steps=["CHALLENGE", "SECOND_FACTOR"], methods=STF),
    Case("O39", "E4", lambda: OB().fixed().who("u_3c4d", "LIB", "2026-11-14T21:00").set(pad=list(L03_PAD)), "DENY",
         {"LIVENESS_UNSURE", "SCHEDULE_GRACE_WINDOW", EXP, OM}, type="CONTACT_DESK"),
    Case("O40", "E4", lambda: OB().fixed().who("u_a3b4", "MAIN", "2026-11-14T21:00").set(pad=list(L03_PAD)), "DENY",
         {"LIVENESS_UNSURE", "SCHEDULE_REVOKED", EXP, OM}, type="CONTACT_DESK"),
    Case("O41", "E5", lambda: OB().fixed().at("2026-11-14T21:00").set(device=PHONE), "DENY",
         {"SPOOF_DEVICE_DETECTED", OM}, type="NONE"),
]


def check(case: Case, res, *, semantics: str = "retries_after") -> None:
    assert res.decision == case.decision, (res.decision, res.reason_codes, res.detail)
    assert set(res.reason_codes) == case.codes
    assert len(res.reason_codes) == len(set(res.reason_codes))
    na = res.next_action
    if case.steps is not None:
        assert list(na.steps) == case.steps
    if case.methods is not None:
        assert set(na.methods or ()) == case.methods
    if case.type is not None:
        assert na.type == case.type
    if na.steps:
        assert na.type == na.steps[0]
    if "SECOND_FACTOR" not in na.steps:
        assert na.methods is None  # methods only when SECOND_FACTOR is required
    if case.mode is not None:
        assert res.mode == case.mode
    if case.attempts_left_doc is not None:
        expected = case.attempts_left_doc + (1 if semantics == "including_next" else 0)
        assert na.attempts_left == expected
    if case.rng_calls is not None:
        assert res.rng_draws == case.rng_calls


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_policy_case(case: Case):
    check(case, case.build().evaluate())


ATTEMPT_CASES = [c for c in CASES if c.attempts_left_doc is not None]


@pytest.mark.parametrize("case", ATTEMPT_CASES, ids=[c.id for c in ATTEMPT_CASES])
def test_attempts_left_alternative_semantics_switch(case: Case):
    """The superseded R15 semantics ("including_next": doc value + 1) remain one YAML switch away."""
    scn = case.build().cfg({"stepup": {"attempts_left_semantics": "including_next"}})
    check(case, scn.evaluate(), semantics="including_next")


# ---------------------------------------------------------------- rows superseded by lead decisions
def test_L04_lead_R11_two_spoof_like_frames_need_a_challenge():
    res = B().set(pad=[0.10, 0.20, 0.90, 0.92, 0.95]).evaluate()
    assert res.decision == "STEP_UP" and set(res.reason_codes) == {"LIVENESS_UNSURE"}
    assert list(res.next_action.steps) == ["CHALLENGE"]


R6_DOC = {  # lead R6 (final): no verified bundle -> DENY SCHEDULE_BUNDLE_INVALID, CONTACT_DESK (docs updating)
    "O24": (lambda: OB().set(bundle=tampered_now()), {INV, OM, OFR}),
    "O25": (lambda: OB().set(bundle=load_example_bundle()), {INV, OM, OFR}),
    "O34": (lambda: B().set(bundle=tampered_now()), {INV, OM, OFR}),
    "O42": (lambda: OB().set(bundle=tampered_now(), pad=list(L03_PAD)), {"LIVENESS_UNSURE", INV, OM, OFR}),
    "O43": (lambda: OB().set(bundle=tampered_now(), local=[("u_3c4d", 0.53, 0.30)] * 5), {"MATCH_LOW", INV, OM, OFR}),
}


@pytest.mark.parametrize("row", sorted(R6_DOC))
def test_no_verified_bundle_lead_R6_denies_contact_desk(row):
    build, doc_codes = R6_DOC[row]
    res = build().evaluate()
    assert res.decision == "DENY"
    assert set(res.reason_codes) == doc_codes - {OFR}  # bio unsure codes + SCHEDULE_BUNDLE_INVALID + OFFLINE_MODE
    assert res.next_action.type == "CONTACT_DESK"
    assert res.mode == "OFFLINE" and res.zone is None and res.schedule_result is None
    assert res.to_response()["zone"] == "UNKNOWN"


# ---------------------------------------------------------------- row-specific extra assertions
def test_Q05_quality_exhausted_has_no_candidate_and_no_schedule():
    res = B().set(luma=[40.0] * 5, recapture_count=2).evaluate()
    body = res.to_response()
    assert body["candidate"] is None and body["schedule_result"] is None and body["bio_result"] is None
    assert body["scores"]["match_local"] is None and body["stage"] == "quality"


def test_Q10_rate_limited_retry_after():
    res = B().set(rate_limit_retry_s=40.0).evaluate()
    assert res.decision == "DENY" and set(res.reason_codes) == {"RATE_LIMITED"}
    assert res.next_action.type == "NONE" and res.next_action.retry_after_s == 40
    assert res.stage == "precheck" and res.cache_state is None


def test_Q10_rate_limit_disabled_never_blocks():
    res = B().cfg({"rate_limit": {"enabled": False}}).set(rate_limit_retry_s=40.0).evaluate()
    assert res.decision == "ALLOW"


def test_Q11_pad_model_exception_is_system_error(monkeypatch):
    from edge.policy import engine

    def boom(*a, **k):
        raise RuntimeError("PAD model crashed")

    monkeypatch.setattr(engine, "liveness_fusion", boom)
    res = B().evaluate()
    assert res.decision == "DENY" and set(res.reason_codes) == {"SYSTEM_ERROR"}
    assert res.next_action.type == "CONTACT_DESK" and res.stage == "system"


def test_Q22_last_recapture_reports_zero_attempts_left():
    assert B().set(luma=[40.0] * 5, recapture_count=1).evaluate().next_action.attempts_left == 0
    assert B().set(luma=[40.0] * 5, recapture_count=0).evaluate().next_action.attempts_left == 1


def test_Q02_recapture_carries_a_hint():
    assert B().set(luma=[40.0] * 5).evaluate().next_action.hint == "more_light"
    assert B().set(secondary=[0.0, 0.7, 0.0, 0.0, 0.0]).evaluate().next_action.hint == "one_person"


@pytest.mark.parametrize("case_id", ["I07", "I14"])
def test_cloud_failure_flips_offline_and_flags_a_heartbeat_miss(case_id):
    case = next(c for c in CASES if c.id == case_id)
    assert case.build().evaluate().cloud_miss is True


@pytest.mark.parametrize("case_id", ["Q01", "I12", "I13", "O30", "O31", "O32", "O36"])
def test_no_heartbeat_miss_without_a_failed_cloud_call(case_id):
    case = next(c for c in CASES if c.id == case_id)
    assert case.build().evaluate().cloud_miss is False


def test_O30_stale_online_bundle_quality_short_circuit_is_offline_too():
    res = B().set(refresh_age_s=31 * 60, luma=[40.0] * 5).evaluate()
    assert set(res.reason_codes) == {"QUALITY_LOW_LIGHT", OM}


def test_O18_revoked_user_purged_from_gallery_is_not_enrolled_lead_R16():
    """Lead R16: refresh purges revoked users' templates, so the gallery cannot return Kiran."""
    res = OB().who("u_a3b4", "MAIN", "2026-11-14T09:00").set(local=[("u_1a2b", 0.21, 0.10)] * 5).evaluate()
    assert set(res.reason_codes) == {"NOT_ENROLLED", OM}


def test_S28_generic_display_message_for_unsure_plus_schedule_deny():
    res = B().who("u_3c4d", "LAB", "2026-11-15T11:00").set(pad=list(L03_PAD)).evaluate()
    assert res.display_message == "Access not available - please contact the desk"


def test_S30_spoof_of_revoked_user_logs_candidate_but_not_schedule():
    res = B().who("u_a3b4", "LIB", "2026-11-14T10:05").set(device=PHONE).evaluate()
    assert res.candidate_user_id == "u_a3b4" and res.schedule_result is None
    body = res.to_response()
    assert body["candidate"] is None and body["cache_state"] is None  # API.md: null on BIO_FAIL


def test_S27_candidate_absent_from_bundle_still_has_a_display_string():
    res = next(c for c in CASES if c.id == "S27").build().evaluate()
    assert res.to_response()["candidate"] == {"user_id": "u_zz99", "display": "u_zz99", "role": None}


def test_response_shape_matches_api_v1_1():
    body = B().evaluate().to_response({"liveness": 100, "match": 200, "bogus": 5})
    assert set(body) == {
        "attempt_id", "kiosk_id", "zone", "decision", "reason_codes", "resolved_codes", "next_action",
        "bio_result", "schedule_result", "mode", "cache_state", "candidate", "scores", "latency_ms",
        "policy_version", "bundle_version", "display_message", "stage",
    }
    assert set(body["next_action"]) == {"type", "steps", "methods", "challenge", "attempts_left", "retry_after_s",
                                        "hint"}
    assert set(body["latency_ms"]) == {"total", "liveness", "match", "schedule", "policy"}
    assert body["candidate"] == {"user_id": "u_3c4d", "display": "Priya N.", "role": "student"}
    assert body["bundle_version"] == 42 and body["policy_version"] == base_thresholds().policy_version
    assert body["zone"] == "LIBRARY" and body["stage"] == "final" and body["cache_state"] == "FRESH"
    assert set(body["scores"]) == {"pad_mean", "pad_pass_frames", "flash_r", "flash_amp", "moire", "device_conf",
                                   "depth", "mask", "match_local", "match_margin", "rekognition",
                                   "rekognition_runner_up", "signals"}
    assert body["scores"]["pad_mean"] == pytest.approx(0.94, abs=1e-3)
    assert body["scores"]["signals"] == {"injection": "PASS", "pad": "PASS", "device": "PASS", "flash": "PASS",
                                         "moire": "PASS", "depth": "NOT_AVAILABLE", "mask": "PASS"}


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_stage_values_are_api_literals(case):
    stage = case.build().evaluate().stage
    assert stage in {"precheck", "quality", "injection", "liveness", "match", "schedule", "mode", "challenge",
                     "fallback", "final", "system"}


def test_LCAL4_weak_amplitude_is_the_ambient_path_not_a_plain_pass():
    from edge.policy.liveness import liveness_fusion

    s = B().set(flash={**B().flash, "r": 0.9, "amplitude": 1.5}).signals()
    T = base_thresholds().with_overrides({"liveness": {"flash": {"enforce": True}}})
    assert liveness_fusion(s.frames, s, "PASS", T, "ONLINE").signals["flash"] == "PASS_AMBIENT"


@pytest.mark.parametrize("lag_ms,fps,decision", [(233.0, 30.0, "ALLOW"), (300.0, 30.0, "DENY"), (175.0, 40.0, "ALLOW")])
def test_lag_in_ms_is_converted_with_the_measured_fps(lag_ms, fps, decision):
    """Robust lag: lag_ms (flash events vs frame timestamps) * fps / 1000 overrides lag_frames."""
    res = B().set(flash=dict(B().flash, r=0.9, lag_frames=1.0, lag_ms=lag_ms, lag_std_ms=20.0, fps=fps)).evaluate()
    assert res.decision == decision


def test_shipped_yaml_random_challenge_restored():
    """Shipped config (user 2026-11-14 "i want that blink"): random challenge back at the documented 0.15
    online / 0.30 offline -> one draw per would-be ALLOW, fires below the rate; lockout from YAML."""
    from edge.policy.ratelimit import RateLimiter

    T = base_thresholds()
    assert T.challenge.random_rate == 0.15 and T.for_mode("OFFLINE").challenge.random_rate == 0.30
    fired = B().set(cfg_patch={}).r(0.0).evaluate()  # RC18 first half (N14)
    assert fired.decision == "STEP_UP" and set(fired.reason_codes) == {"RANDOM_CHALLENGE"} and fired.rng_draws == 1
    assert fired.next_action.type == "CHALLENGE" and list(fired.next_action.steps) == ["CHALLENGE"]
    passed = B().set(cfg_patch={}).r(0.99).evaluate()  # RC18 second half (N1)
    assert passed.decision == "ALLOW" and set(passed.reason_codes) == {"ACCESS_OK"} and passed.rng_draws == 1
    assert passed.next_action.type == "OPEN_DOOR"
    assert RateLimiter(T).lockout_s == float(T.rate_limit.lockout_s)


def test_evaluate_is_deterministic():
    assert B().evaluate().to_response() == B().evaluate().to_response()


def test_shipped_yaml_unknown_camera_label_does_not_step_up():
    """Operator 2026-11-14: step-up only when suspicious. Unknown non-virtual label -> PASS; virtual -> DENY."""
    assert B().set(cfg_patch={}, label="MacBook Pro Camera").evaluate().decision == "ALLOW"
    assert B().set(cfg_patch={}, label="").evaluate().decision == "ALLOW"
    d = B().set(cfg_patch={}, label="OBS Virtual Camera").evaluate()
    assert d.decision == "DENY" and d.reason_codes == ("INJECTION_VIRTUAL_CAMERA",)
