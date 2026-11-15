"""Test builders: baseline fixture `B` / `OB` of docs/POLICY_TEST_CASES.md (policy 2026-11-14.2) + deltas.

Everything here is test-only. Keys/secrets are fixture values, never the .env values.
Bundle stamps: unless a case says `fixed stamps`, the fixture signs at `now` (issued_at = now - 5 min,
expires_at = issued_at + 12 h) -> FRESH at any t0. `fixed stamps` = the example file (02:30Z / 14:30Z).
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from edge.policy.signals import (
    ActionEvidence,
    AttemptSignals,
    CameraMeta,
    ChallengeEvidence,
    CloudMatch,
    DepthSignal,
    FlashSignal,
    FrameQuality,
    FrameSignals,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
CONFIG_DIR = PROJECT_ROOT / "config"
THRESHOLDS_PATH = CONFIG_DIR / "thresholds.yaml"
SCHEDULE_EXAMPLE_PATH = CONFIG_DIR / "schedule.example.json"

IST = ZoneInfo("Asia/Kolkata")

# Fixture-only keys (NOT the .env values).
TEST_BUNDLE_KEY = b"test-bundle-hmac-key-0123456789"
TEST_CARD_PEPPER = b"hidhack-demo-pepper"  # documented demo pepper the example card hashes use
TEST_DATA_KEY = "y7xQb0p1yB8m1n9Gd3o6tVv0gQK1Xb2qJ4b8m2Z9s3E="  # Fernet-format test key
TEST_KIOSK_KEY = b"test-kiosk-hmac-key"

TOTP_SECRETS = {
    "u_3c4d": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    "u_1a2b": "KRSXG5CTMVRXEZLUKRSXG5CTMVRXEZLU",
    "u_7a8b": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
    "u_c5d6": "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK",
}

KIOSK = {
    "LIB": "KIOSK_LIB_01",
    "LAB": "KIOSK_LAB_01",
    "HOSTEL": "KIOSK_HOSTEL_01",
    "SRV": "KIOSK_SRV_01",
    "MAIN": "KIOSK_MAIN_01",
}

B_T0 = datetime(2026, 11, 14, 10, 5, tzinfo=IST)  # Saturday, = 04:35:00Z


class AnchoredClock:
    """Injected real clock for runtime tests: starts at `start` and advances with real (monotonic) elapsed time,
    so step-up TTLs still run but the time of day never depends on the host clock (a suite run at 21:15 IST
    must not hit SCHEDULE_OUTSIDE_WINDOW). Pass to PolicyRuntime.from_env(clock=...)."""

    def __init__(self, start: datetime) -> None:
        self._start = start.astimezone(UTC)
        self._mono0 = time.monotonic()
        self._jump = timedelta(0)

    def __call__(self) -> datetime:
        return self._start + self._jump + timedelta(seconds=time.monotonic() - self._mono0)

    def advance(self, delta: timedelta) -> None:
        """Jump the injected real clock forward (expiry tests); undone by reset()."""
        self._jump += delta

    def reset(self) -> None:
        """Re-anchor: `now` is `start` again. The shared RT_CLOCK is reset before every test (autouse fixture in
        the edge/policy + edge/offline conftests), so no test sees the real time the suite has already spent
        (a bundle signed at `now - 5 min` then has whole-minute stamps, whatever ran before)."""
        self._mono0 = time.monotonic()
        self._jump = timedelta(0)


RT_CLOCK = AnchoredClock(B_T0)  # Sat 10:05 IST: inside every baseline window (shared by make_rt and attempt())
B_PAD = [0.95, 0.93, 0.94, 0.92, 0.96]
L03_PAD = [0.85, 0.82, 0.60, 0.50, 0.70]
O14_PAD = [0.83, 0.82, 0.84, 0.81, 0.83]
PHONE = [(0.62, 1.0)] * 5
DEPTH_PASS = {
    "available": True,
    "absolute": True,
    "d0_valid_ratio": 0.90,
    "d1_plane_rms_mm": 9.0,
    "d2_quad_rms_mm": 6.0,
    "d3_nose_relief_mm": 22.0,
    "d4_ipd_mm": 63.0,
}


# The vectors test the DOCUMENTED rules, so every operator switch of config/thresholds.yaml that differs from
# (or may later differ from) the doc baseline is pinned here; everything else (incl. the 5 s rate-limit lockout)
# is read from the YAML. The shipped profile itself is exercised by test_invariants (P01-P13 fuzz).
DOC_BASELINE_PATCH = {
    "challenge": {"random_rate": 0.15},
    "offline": {"overrides": {"challenge": {"random_rate": 0.30}}},
    # flash ADVISORY in the shipped YAML (enforce: false, lead 2026-11-14); moire / RGB-M2 switches may be
    # flipped to advisory the same way -> the vectors test enforcement
    "liveness": {"flash": {"enforce": True}, "moire": {"enforce": True}, "mask": {"m2_rgb_enforce": True}},
    # shipped YAML: unknown camera label no longer steps up (operator 2026-11-14); §3.2 / Q09 test the doc rule
    "injection": {"unknown_label_is_unsure": True},
    # online identity = Rekognition in the doc rows (the switch is an operator workaround, §3.5)
    "match": {"rekognition": {"enabled": True}},
}
# Fixture override codes (config/schedule.example.json, publicly documented): code value -> staff_id. Every
# STAFF_OVERRIDE submission names its staff member (R2); harnesses add it unless a test passes staff_id itself.
FIXTURE_STAFF = {"48213907": "s_guard01", "75530182": "s_guard01", "19064425": "s_guard02"}


def with_staff(sub: dict) -> dict:
    if sub.get("method") == "STAFF_OVERRIDE" and "staff_id" not in sub:
        return {**sub, "staff_id": FIXTURE_STAFF.get(sub.get("code") or "", "s_guard01")}
    return sub


def ist(s: str) -> datetime:
    """'2026-11-14T07:50' -> aware IST datetime."""
    return datetime.fromisoformat(s).replace(tzinfo=IST)


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=UTC)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_example_bundle() -> dict:
    return json.loads(SCHEDULE_EXAMPLE_PATH.read_text(encoding="utf-8"))


def sign_fixture_bundle(bundle: dict, key: bytes = TEST_BUNDLE_KEY) -> dict:
    """Independent re-implementation of the documented signing scheme (for fixtures)."""
    b = copy.deepcopy(bundle)
    b.pop("signature", None)
    sig = hmac.new(key, canonical(b), hashlib.sha256).hexdigest()
    b["signature"] = {"alg": "HMAC-SHA256", "key_id": "test-k1", "value": sig}
    return b


def bundle_signed_at(now: datetime, *, code_grace_h: float = 24.0) -> dict:
    """The fixture 'signs at now like scripts/sign_bundle.py': issued_at = now - 5 min, +12 h expiry.
    Override valid_until = expires_at + 24 h (lead R7 / YAML valid_after_expiry_h)."""
    b = load_example_bundle()
    issued = now - timedelta(minutes=5)
    expires = issued + timedelta(hours=12)
    b["issued_at"], b["expires_at"] = iso_z(issued), iso_z(expires)
    for c in b["override_codes"]["codes"]:
        c["valid_until"] = iso_z(expires + timedelta(hours=code_grace_h))
    return sign_fixture_bundle(b)


SIGNED_BUNDLE = sign_fixture_bundle(load_example_bundle())  # `fixed stamps`


def tampered(bundle: dict) -> dict:
    b = copy.deepcopy(bundle)
    b["roles"]["student"]["windows"]["LIBRARY"][0]["end"] = "23:59"  # one window edited after signing
    return b


class StubRng:
    """Injected ctx.rng: returns a fixed value and counts calls (RC17 / P09)."""

    def __init__(self, value: float = 0.99) -> None:
        self.value, self.calls = value, 0

    def random(self) -> float:
        self.calls += 1
        return self.value


def frames_from(pad, *, luma, lapvar, yaw, secondary, device, moire, ring, local, ts, depth_valid) -> list[FrameSignals]:
    out = []
    for i, p in enumerate(pad):
        out.append(
            FrameSignals(
                index=i,
                ts_ms=ts[i],
                quality=FrameQuality(
                    face_count=2 if secondary[i] > 0 else 1,
                    secondary_face_rel_size=secondary[i],
                    luma_mean=luma[i],
                    overexposed_frac=0.0,
                    laplacian_var=lapvar[i],
                    face_width_px=220.0,
                    iod_px=85.0,
                    yaw_deg=yaw[i],
                    pitch_deg=2.0,
                    roll_deg=1.0,
                    depth_valid_ratio=depth_valid[i],
                ),
                pad_v2=p,
                pad_v1se=p,
                device_conf=device[i][0],
                device_face_containment=device[i][1],
                moire=moire[i],
                mask_edge_ring=ring[i],
                match_top1_user=local[i][0],
                match_top1=local[i][1],
                match_top2=local[i][2],
            )
        )
    return out


@dataclass
class Scn:
    """Baseline fixture B (+ deltas). `.build()` -> (signals, schedule_ctx, mode, now, T)."""

    mode: str = "ONLINE"
    kiosk_id: str = "KIOSK_LIB_01"
    t0: datetime = B_T0
    now: datetime | None = None  # default = t0
    pad: list[float] = field(default_factory=lambda: list(B_PAD))
    luma: list[float] = field(default_factory=lambda: [120.0] * 5)
    lapvar: list[float] = field(default_factory=lambda: [150.0] * 5)
    yaw: list[float] = field(default_factory=lambda: [5.0] * 5)
    secondary: list[float] = field(default_factory=lambda: [0.0] * 5)
    label: str = "FaceTime HD Camera"
    ts: list[int] = field(default_factory=lambda: [1_000 + 33 * i for i in range(5)])
    device: list[tuple[float, float]] = field(default_factory=lambda: [(0.0, 0.0)] * 5)
    moire: list[float | None] = field(default_factory=lambda: [0.10] * 5)
    ring: list[float | None] = field(default_factory=lambda: [0.10] * 5)
    local: list[tuple[str | None, float | None, float | None]] = field(
        default_factory=lambda: [("u_3c4d", 0.72, 0.41)] * 5
    )
    flash: dict | None = field(
        default_factory=lambda: {"r": 0.85, "amplitude": 9.0, "lag_frames": 1.0, "lag_std_frames": 0.5, "order_ok": True}
    )
    flash_enabled: bool = True
    depth: dict | None = None
    depth_valid: list[float | None] = field(default_factory=lambda: [None] * 5)
    cloud: dict | None = field(
        default_factory=lambda: {"ok": True, "top1_user": "u_3c4d", "top1_similarity": 99.6, "runner_up_similarity": None}
    )
    cache_age_h: float | None = 1.0
    recapture_count: int = 0
    cfg_patch: dict = field(default_factory=lambda: copy.deepcopy(DOC_BASELINE_PATCH))
    fixed_stamps: bool = False
    bundle: dict | None = None  # explicit bundle (tampered / unsigned); default = signed per stamps rule
    signature_valid: bool | None = None  # None -> verify with TEST_BUNDLE_KEY
    no_bundle: bool = False
    refresh_age_s: float | None = 300.0  # last successful refresh 5 min before now (MO1)
    rate_limit_retry_s: float | None = None
    rng: Any = field(default_factory=lambda: StubRng(0.99))
    attempt_id: str = "att_TEST0001"

    # ---------------------------------------------------------------- deltas
    def offline(self) -> Scn:
        self.mode = "OFFLINE"
        self.cloud = None
        return self

    def who(self, user: str, kiosk: str, local_time: str) -> Scn:
        self.kiosk_id = KIOSK[kiosk]
        self.t0 = ist(local_time)
        self.now = self.t0
        self.local = [(user, 0.72, 0.41)] * 5
        if self.cloud is not None:
            self.cloud = dict(self.cloud, top1_user=user)
        return self

    def at(self, local_time: str) -> Scn:
        self.t0 = self.now = ist(local_time)
        return self

    def fixed(self) -> Scn:
        self.fixed_stamps = True
        return self

    def cfg(self, patch: dict) -> Scn:
        _deep_update(self.cfg_patch, patch)
        return self

    def depth_on(self, **depth) -> Scn:
        self.cfg({"liveness": {"depth": {"enabled": True}}})
        self.depth = dict(DEPTH_PASS, **depth)
        return self

    def r(self, value: float) -> Scn:
        self.rng = StubRng(value)
        return self

    def set(self, **kw) -> Scn:
        for k, v in kw.items():
            setattr(self, k, v)
        return self

    # ---------------------------------------------------------------- build
    @property
    def eff_now(self) -> datetime:
        return self.now or self.t0

    def thresholds(self):
        base = base_thresholds()
        return base.with_overrides(self.cfg_patch) if self.cfg_patch else base

    def the_bundle(self) -> dict | None:
        if self.no_bundle:
            return None
        if self.bundle is not None:
            return self.bundle
        return copy.deepcopy(SIGNED_BUNDLE) if self.fixed_stamps else bundle_signed_at(self.eff_now)

    def signals(self) -> AttemptSignals:
        frames = frames_from(self.pad, luma=self.luma, lapvar=self.lapvar, yaw=self.yaw, secondary=self.secondary,
                             device=self.device, moire=self.moire, ring=self.ring, local=self.local, ts=self.ts,
                             depth_valid=self.depth_valid)
        return AttemptSignals(
            attempt_id=self.attempt_id,
            kiosk_id=self.kiosk_id,
            t0=self.t0,
            recapture_count=self.recapture_count,
            frames=frames,
            camera=CameraMeta(camera_label=self.label, frame_timestamps_ms=list(self.ts)),
            flash=FlashSignal(**self.flash) if self.flash is not None else None,
            flash_enabled=self.flash_enabled,
            depth=DepthSignal(**self.depth) if self.depth is not None else None,
            cloud_match=CloudMatch(**self.cloud) if self.cloud is not None else None,
            template_cache_age_h=self.cache_age_h,
        )

    def schedule_ctx(self):
        from edge.policy.engine import ScheduleCtx

        bundle = self.the_bundle()
        valid = self.signature_valid
        if valid is None:
            valid = _fixture_signature_ok(bundle)
        return ScheduleCtx(kiosk_id=self.kiosk_id, bundle=bundle, signature_valid=valid,
                           refresh_age_s=self.refresh_age_s)

    def build(self):
        return self.signals(), self.schedule_ctx(), self.mode, self.eff_now, self.thresholds()

    def evaluate(self):
        from edge.policy.engine import evaluate

        signals, ctx, mode, now, T = self.build()
        return evaluate(signals, ctx, mode, now, cfg=T, rate_limit_retry_s=self.rate_limit_retry_s, rng=self.rng)

    def copy(self) -> Scn:
        return replace(self, cfg_patch=copy.deepcopy(self.cfg_patch), bundle=copy.deepcopy(self.bundle))


_BASE_T = None


def base_thresholds():
    """config/thresholds.yaml parsed once per test session (Thresholds objects are immutable)."""
    global _BASE_T
    if _BASE_T is None:
        from edge.policy.thresholds import Thresholds

        _BASE_T = Thresholds.load(THRESHOLDS_PATH)
    return _BASE_T


def enforced_thresholds():
    """The shipped YAML with every documented enforcement switch on (flash, moire, RGB mask ring)."""
    return base_thresholds().with_overrides(
        {"liveness": {"flash": {"enforce": True}, "moire": {"enforce": True}, "mask": {"m2_rgb_enforce": True}}})


def _fixture_signature_ok(bundle: dict | None) -> bool:
    if not bundle or not isinstance(bundle.get("signature"), dict):
        return False
    b = copy.deepcopy(bundle)
    sig = b.pop("signature")
    expected = hmac.new(TEST_BUNDLE_KEY, canonical(b), hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(sig.get("value", "")), expected)


def _deep_update(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_update(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def B() -> Scn:
    return Scn()


def OB() -> Scn:
    return Scn().offline()


# ---------------------------------------------------------------- challenge evidence helpers
def action(name: str, *, prompt: int, start_after: int | None = 400, complete_after: int | None = 650,
           baseline: float = 0.05, peak: float = 0.62, shift: float | None = 0.12, yaw: float | None = None,
           lost: bool = False) -> ActionEvidence:
    return ActionEvidence(
        action=name,
        prompted_at_ms=prompt,
        started_at_ms=None if start_after is None else prompt + start_after,
        completed_at_ms=None if complete_after is None else prompt + complete_after,
        baseline=baseline,
        peak=peak,
        landmark_shift=shift,
        yaw_peak_deg=yaw,
        tracking_lost=lost,
    )


def good_action(name: str, prompt: int) -> ActionEvidence:
    if name == "SMILE":
        return action(name, prompt=prompt, baseline=0.07, peak=0.62)
    if name == "OPEN_MOUTH":
        return action(name, prompt=prompt, baseline=0.03, peak=0.60)
    if name == "PUFF_CHEEKS":
        return action(name, prompt=prompt, baseline=0.02, peak=0.55)
    if name == "BLINK":
        return action(name, prompt=prompt, baseline=0.08, peak=0.85, shift=None)
    if name == "TURN_LEFT":
        return action(name, prompt=prompt, start_after=700, complete_after=950, baseline=0.0, peak=0.0,
                      shift=None, yaw=20.0)
    if name == "TURN_RIGHT":
        return action(name, prompt=prompt, start_after=700, complete_after=950, baseline=0.0, peak=0.0,
                      shift=None, yaw=-20.0)
    raise ValueError(name)


def no_deformation(name: str, prompt: int) -> ActionEvidence:
    """A deformation step without any qualifying response (eye-cut paper mask: rise 0.05)."""
    return action(name, prompt=prompt, baseline=0.07, peak=0.12, shift=0.0)


def evidence_for(challenge, actions: list[ActionEvidence] | None = None, **kw) -> ChallengeEvidence:
    """Evidence answering `challenge` (all actions good unless `actions` given)."""
    acts = actions or [good_action(a, 10_000 + 2_000 * i) for i, a in enumerate(challenge.actions)]
    params = {"same_track": True, "last_frame_cosine": 0.68, "depth": None}
    params.update(kw)
    return ChallengeEvidence(challenge_id=challenge.challenge_id, nonce=challenge.nonce, actions=acts, **params)


def soft_fail_evidence(challenge) -> ChallengeEvidence:
    acts = [no_deformation(a, 10_000 + 2_000 * i) if a in ("SMILE", "OPEN_MOUTH", "PUFF_CHEEKS")
            else good_action(a, 10_000 + 2_000 * i) for i, a in enumerate(challenge.actions)]
    return evidence_for(challenge, actions=acts)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)
