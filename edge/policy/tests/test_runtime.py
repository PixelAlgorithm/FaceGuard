"""PolicyRuntime end to end (in-process, temp data dir, mocked cloud -- never the live :8000 edge).

Regression guard for a half-applied refactor: decide() must drive the real engine with a matched
candidate (BIO_PASS -> ALLOW), and every response must validate against the docs/API.md v1.1
DecisionResponse contract (extra="forbid"), re-declared below as an independent oracle.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Literal

import httpx
import pyotp
import pytest
from pydantic import BaseModel, ConfigDict, Field, model_validator

from edge.offline.bundle import sign_bundle
from edge.policy.runtime import AttemptClosedError, AttemptNotFoundError, CloudUnavailableError, PolicyRuntime
from edge.policy.signals import FallbackSubmission
from edge.policy.tests.builders import (
    L03_PAD,
    PROJECT_ROOT,
    RT_CLOCK,
    TEST_BUNDLE_KEY,
    TEST_CARD_PEPPER,
    TEST_DATA_KEY,
    TEST_KIOSK_KEY,
    TOTP_SECRETS,
    B,
    evidence_for,
    load_example_bundle,
)


# ---------------------------------------------------------------- API.md v1.1 §1 contract (oracle)
class _Out(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ChallengeSpec(_Out):
    challenge_id: str
    nonce: str
    actions: list[Literal["SMILE", "OPEN_MOUTH", "PUFF_CHEEKS", "BLINK", "TURN_LEFT", "TURN_RIGHT"]] = Field(
        min_length=2, max_length=2)
    step_window_ms: int
    min_reaction_ms: int
    expires_at: datetime


class NextAction(_Out):
    type: Literal["OPEN_DOOR", "RECAPTURE", "CHALLENGE", "SECOND_FACTOR", "CONTACT_DESK", "NONE"]
    steps: list[Literal["CHALLENGE", "SECOND_FACTOR"]] = Field(default_factory=list)
    methods: list[Literal["TOTP", "CARD", "EMAIL_OTP", "STAFF_OVERRIDE"]] | None = None
    challenge: ChallengeSpec | None = None
    attempts_left: int | None = None
    retry_after_s: int | None = None
    hint: Literal["move_closer", "more_light", "hold_still", "one_person", "face_camera"] | None = None

    @model_validator(mode="after")
    def _shape(self):
        if self.type in ("CHALLENGE", "SECOND_FACTOR"):
            assert self.steps and self.steps[0] == self.type
        else:
            assert not self.steps
        assert (self.challenge is not None) == (self.type == "CHALLENGE")
        assert (self.methods is not None) == ("SECOND_FACTOR" in self.steps)
        return self


class Candidate(_Out):
    user_id: str
    display: str
    role: str | None = None  # lead 2026-11-14: role shown on PASS (API.md update pending)


SignalName = Literal["pad", "device", "moire", "flash", "mask", "depth", "injection"]
SignalStatus = Literal["PASS", "PASS_AMBIENT", "UNSURE", "FAIL", "NOT_AVAILABLE",
                       "ADVISORY_PASS", "ADVISORY_UNSURE", "ADVISORY_FAIL", "ADVISORY_WEAK"]


class Scores(_Out):
    pad_mean: float | None = None
    pad_pass_frames: int | None = None
    flash_r: float | None = None
    flash_amp: float | None = None
    moire: float | None = None
    device_conf: float | None = None
    depth: dict[str, float | None] | None = None
    mask: dict[str, float] = Field(default_factory=dict)
    match_local: float | None = None
    match_margin: float | None = None
    rekognition: float | None = None
    rekognition_runner_up: float | None = None
    # lead 2026-11-14 (operator view; API.md update pending): per-signal status, null when liveness never ran
    signals: dict[SignalName, SignalStatus] | None = None

    @model_validator(mode="after")
    def _all_signals(self):
        assert self.signals is None or set(self.signals) == set(SignalName.__args__), self.signals
        return self


class LatencyMs(_Out):
    total: int
    liveness: int
    match: int
    schedule: int
    policy: int


class DecisionResponse(_Out):
    attempt_id: str
    kiosk_id: str
    zone: str
    decision: Literal["ALLOW", "STEP_UP", "DENY"]
    reason_codes: list[str] = Field(min_length=1)
    resolved_codes: list[str] = Field(default_factory=list)
    next_action: NextAction
    bio_result: Literal["BIO_PASS", "BIO_UNSURE", "BIO_FAIL"] | None
    schedule_result: str | None
    mode: Literal["ONLINE", "OFFLINE"]
    cache_state: Literal["FRESH", "EXPIRED", "INVALID"] | None
    candidate: Candidate | None
    scores: Scores
    latency_ms: LatencyMs
    policy_version: str
    bundle_version: int | None
    display_message: str
    stage: Literal["precheck", "quality", "injection", "liveness", "match", "schedule", "mode", "challenge",
                   "fallback", "final", "system"]

    @model_validator(mode="after")
    def _invariants(self):
        codes, t = set(self.reason_codes), self.next_action.type
        assert ("OFFLINE_MODE" in codes) == (self.mode == "OFFLINE")
        assert (self.decision == "ALLOW") == (t == "OPEN_DOOR")
        assert self.decision != "ALLOW" or "ACCESS_OK" in codes
        assert self.decision != "STEP_UP" or t in ("RECAPTURE", "CHALLENGE", "SECOND_FACTOR")
        assert self.decision != "DENY" or t in ("CONTACT_DESK", "NONE")
        assert self.bio_result != "BIO_FAIL" or (self.candidate is None and self.schedule_result is None)
        assert not self.resolved_codes or self.decision == "ALLOW"
        return self


def ok(body: dict) -> dict:
    DecisionResponse.model_validate(body)
    return body


# ---------------------------------------------------------------- fixtures
def _signed_now(now: datetime) -> dict:
    b = load_example_bundle()
    b["issued_at"] = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    b["expires_at"] = (now + timedelta(hours=11, minutes=55)).strftime("%Y-%m-%dT%H:%M:%SZ")
    for c in b["override_codes"]["codes"]:
        c["valid_until"] = (now + timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return sign_bundle(b, TEST_BUNDLE_KEY)


class FakeCloud:
    """Minimal cloud: /v1/health, /v1/revocations, /v1/schedule/{kiosk}, /v1/sync (API.md 4.2-4.4)."""

    def __init__(self, bundle: dict) -> None:
        self.bundle, self.up, self.stored, self.revocations = bundle, True, {}, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if not self.up:
            raise httpx.ConnectError("cloud down", request=request)
        p = request.url.path
        if p == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if p == "/v1/revocations":
            return httpx.Response(200, json={"revocation_seq": len(self.revocations), "items": self.revocations})
        if p.startswith("/v1/schedule/"):
            return httpx.Response(200, json=self.bundle)
        if p == "/v1/sync":
            body = json.loads(request.content)
            acc, dup = [], []
            for it in body["items"]:
                if it.get("type") == "TOMBSTONE":
                    continue
                k = it["idempotency_key"]
                (dup if k in self.stored else acc).append(k)
                self.stored[k] = it
            return httpx.Response(200, json={"accepted": acc, "duplicates": dup, "rejected": [], "flags": [],
                                             "server_time": "2026-11-14T04:58:41Z"})
        return httpx.Response(404)


@pytest.fixture
def make_rt(tmp_path):
    def make(kiosk="KIOSK_LIB_01", cloud: FakeCloud | None = None, **extra_env):
        now = RT_CLOCK()
        bundle = _signed_now(now)
        (tmp_path / "bundle.signed.json").write_text(json.dumps(bundle), encoding="utf-8")
        env = {"KIOSK_ID": kiosk, "EDGE_DATA_KEY": TEST_DATA_KEY, "SCHEDULE_BUNDLE_HMAC_KEY": TEST_BUNDLE_KEY.decode(),
               "CARD_ID_PEPPER": TEST_CARD_PEPPER.decode(), "KIOSK_HMAC_KEY": TEST_KIOSK_KEY.decode(),
               "EDGE_DATA_DIR": str(tmp_path), "CLOUD_API_URL": "https://cloud.test" if cloud else ""}
        env.update(extra_env)
        rt = PolicyRuntime.from_env(PROJECT_ROOT, env=env,
                                    transport=httpx.MockTransport(cloud) if cloud else None, clock=RT_CLOCK)
        rt.set_random_challenge("OFF")
        for uid, secret in TOTP_SECRETS.items():
            rt.set_totp_secret(uid, secret)
        return rt
    return make


def attempt(aid: str, **deltas):
    scn = B().set(attempt_id=aid, **deltas)
    return scn.signals().model_copy(update={"t0": RT_CLOCK()})


def bring_online(rt) -> None:
    for _ in range(3):
        rt.heartbeat()
    rt.sync_now()  # SYNCING -> queue acked + bundle refreshed -> ONLINE


# ---------------------------------------------------------------- tests
def test_decide_matched_candidate_offline_allows_and_logs(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_rt_allow_off"), latency_ms={"total": 400, "liveness": 120, "match": 90}))
    assert body["decision"] == "ALLOW" and set(body["reason_codes"]) == {"ACCESS_OK", "OFFLINE_MODE"}
    assert body["candidate"] == {"user_id": "u_3c4d", "display": "Priya N.", "role": "student"}
    assert body["latency_ms"]["total"] >= 400 and body["latency_ms"]["liveness"] == 120
    recs = rt.store_view()["records"]
    assert [r["attempt_id"] for r in recs] == ["att_rt_allow_off"] and recs[0]["user_id"] == "u_3c4d"


def test_decide_matched_candidate_online_allows(make_rt):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    assert rt.mode() == "ONLINE"
    body = ok(rt.decide(attempt("att_rt_allow_on")))
    assert body["decision"] == "ALLOW" and body["reason_codes"] == ["ACCESS_OK"] and body["mode"] == "ONLINE"


def test_spoof_denies_and_unsure_steps_up(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_rt_phone", device=[(0.62, 1.0)] * 5)))
    assert body["decision"] == "DENY" and "SPOOF_DEVICE_DETECTED" in body["reason_codes"]
    body = ok(rt.decide(attempt("att_rt_unsure", pad=list(L03_PAD))))
    assert body["decision"] == "STEP_UP" and body["next_action"]["challenge"] is not None


def test_step_up_challenge_then_totp_offline(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_rt_su", pad=list(L03_PAD))))
    assert body["next_action"]["steps"] == ["CHALLENGE", "SECOND_FACTOR"]
    ch = rt.sessions["att_rt_su"].challenge
    body = ok(rt.resolve_challenge("att_rt_su", evidence_for(ch)))
    assert body["decision"] == "STEP_UP" and body["next_action"]["steps"] == ["SECOND_FACTOR"]
    code = pyotp.TOTP(TOTP_SECRETS["u_3c4d"]).at(int(rt.real_now().timestamp()))
    body = ok(rt.resolve_fallback("att_rt_su", FallbackSubmission(method="TOTP", code=code)))
    assert body["decision"] == "ALLOW" and body["resolved_codes"] == ["LIVENESS_UNSURE"]
    with pytest.raises(AttemptClosedError):
        rt.resolve_fallback("att_rt_su", FallbackSubmission(method="TOTP", code=code))
    with pytest.raises(AttemptClosedError):
        rt.decide(attempt("att_rt_su"))
    with pytest.raises(AttemptNotFoundError):
        rt.resolve_challenge("att_never_seen", evidence_for(ch))


def test_invalid_input_dict_is_deny_system_error_not_an_exception(make_rt):
    rt = make_rt()
    body = ok(rt.decide({"attempt_id": "att_rt_bad", "frames": "nope"}))
    assert body["decision"] == "DENY" and "SYSTEM_ERROR" in body["reason_codes"] and body["stage"] == "system"


def test_decide_error_logs_system_error(make_rt):
    rt = make_rt()
    body = ok(rt.decide_error("att_rt_crash", detail="PAD model crashed"))
    assert body["decision"] == "DENY" and set(body["reason_codes"]) == {"SYSTEM_ERROR", "OFFLINE_MODE"}
    assert rt.store_view()["records"][0]["attempt_id"] == "att_rt_crash"


def test_record_write_failure_never_allows(make_rt, monkeypatch):
    rt = make_rt()

    def broken(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(rt.log, "append_final", broken)
    body = ok(rt.decide(attempt("att_rt_diskfull")))
    assert body["decision"] == "DENY" and "SYSTEM_ERROR" in body["reason_codes"]


def test_client_t0_is_rebased_onto_the_edge_clock(make_rt):
    rt = make_rt()
    s = attempt("att_rt_t0").model_copy(update={"t0": datetime(2026, 1, 1, tzinfo=UTC)})
    body = ok(rt.decide(s))
    assert body["decision"] == "ALLOW"  # a forged 1 Jan t0 is clamped to "now - <=10 s"


def test_sync_now_without_cloud_is_cloud_unavailable(make_rt):
    rt = make_rt()
    with pytest.raises(CloudUnavailableError):
        rt.sync_now()


def test_mode_status_shape(make_rt):
    rt = make_rt()
    st = rt.mode_status()
    assert {"mode", "state", "since", "forced", "last_cloud_ok_at", "reason", "schedule_bundle", "revocation_seq",
            "template_cache", "sync_queue_depth", "demo_clock"} <= set(st)
    assert st["mode"] == "OFFLINE" and st["reason"] == "not_configured" and st["demo_clock"] is None
    assert {"version", "issued_at", "expires_at", "signature_valid", "cache_state"} <= set(st["schedule_bundle"])
    assert {"count", "model", "age_h"} <= set(st["template_cache"])


def test_decide_fast_enough(make_rt):
    rt = make_rt()
    import time

    t = time.perf_counter()
    for i in range(20):
        rt.decide(attempt(f"att_rt_fast_{i}"))
    per_ms = (time.perf_counter() - t) * 1000 / 20
    assert per_ms < 20, per_ms  # incl. the encrypted SQLite write


def test_user_info_from_the_verified_bundle(make_rt):
    rt = make_rt()
    assert rt.user_info("u_7a8b") == {"user_id": "u_7a8b", "display": "Rahul V.", "role": "staff"}
    assert rt.user_info("u_nobody") is None


def test_runtime_drop_method_reissues_without_counting(make_rt):
    rt = make_rt()
    body = ok(rt.decide(attempt("att_rt_drop", pad=list(L03_PAD))))  # offline: CH -> SF{off}
    assert "EMAIL_OTP" not in body["next_action"]["methods"]
    body2 = ok(rt.drop_method("att_rt_drop", "CARD"))
    assert set(body2["next_action"]["methods"]) == {"TOTP", "STAFF_OVERRIDE"}
    assert body2["next_action"]["attempts_left"] == body["next_action"]["attempts_left"]
    assert rt.get_attempt("att_rt_drop")["next_action"]["methods"] == body2["next_action"]["methods"]
    assert rt.limiter.state()["events"] == []
    with pytest.raises(AttemptNotFoundError):
        rt.drop_method("att_unknown", "EMAIL_OTP")


# ---------------------------------------------------------------- lead 2026-11-14 batch
ZERO_RATE = {"challenge": {"random_rate": 0.0}, "offline": {"overrides": {"challenge": {"random_rate": 0.0}}}}


def test_force_next_fires_exactly_once_even_at_a_zero_rate_then_auto(make_rt):
    rt = make_rt()
    rt.cfg = rt.cfg.with_overrides(ZERO_RATE)
    rt.set_random_challenge("FORCE_NEXT")
    body = ok(rt.decide(attempt("att_rt_fn_1")))
    assert body["decision"] == "STEP_UP" and set(body["reason_codes"]) == {"RANDOM_CHALLENGE", "OFFLINE_MODE"}
    assert body["next_action"]["type"] == "CHALLENGE" and body["next_action"]["steps"] == ["CHALLENGE"]
    assert rt.mode_status()["random_challenge"] == "AUTO"
    body = ok(rt.decide(attempt("att_rt_fn_2")))
    assert body["decision"] == "ALLOW" and set(body["reason_codes"]) == {"ACCESS_OK", "OFFLINE_MODE"}


def test_force_next_waits_for_a_would_be_allow(make_rt):
    rt = make_rt()
    rt.cfg = rt.cfg.with_overrides(ZERO_RATE)
    rt.set_random_challenge("FORCE_NEXT")
    body = ok(rt.decide(attempt("att_rt_fn_deny", device=[(0.62, 1.0)] * 5)))  # DENY: no draw, still armed
    assert body["decision"] == "DENY" and rt.mode_status()["random_challenge"] == "FORCE_NEXT"
    body = ok(rt.decide(attempt("att_rt_fn_ok")))
    assert "RANDOM_CHALLENGE" in body["reason_codes"] and rt.mode_status()["random_challenge"] == "AUTO"


def test_force_fires_on_every_would_be_allow_at_a_zero_rate_and_off_never(make_rt):
    rt = make_rt()
    rt.cfg = rt.cfg.with_overrides(ZERO_RATE)
    rt.set_random_challenge("FORCE")
    for i in range(3):
        assert "RANDOM_CHALLENGE" in ok(rt.decide(attempt(f"att_rt_force_{i}")))["reason_codes"]
    assert rt.mode_status()["random_challenge"] == "FORCE"
    rt.cfg = rt.cfg.with_overrides({"challenge": {"random_rate": 1.0},
                                    "offline": {"overrides": {"challenge": {"random_rate": 1.0}}}})
    rt.set_random_challenge("OFF")
    assert ok(rt.decide(attempt("att_rt_off")))["decision"] == "ALLOW"


def test_policy_bars_report_the_bars_the_engine_applies(make_rt):
    rt = make_rt()  # offline: OFFLINE bars
    bars = rt.mode_status()["policy_bars"]
    T_off = rt.cfg.for_mode("OFFLINE")
    assert bars["match_allow"] == T_off.match.local.allow_min_cosine
    assert bars["match_margin"] == T_off.match.local.min_margin_top1_top2
    assert bars["moire_unsure"] == T_off.liveness.moire.unsure_score
    assert bars["device_unsure"] == T_off.liveness.device_detector.unsure_conf
    assert {k: type(bars[k]) for k in ("flash_enforce", "moire_enforce", "m2_rgb_enforce", "rekognition")} == {
        "flash_enforce": bool, "moire_enforce": bool, "m2_rgb_enforce": bool, "rekognition": bool}
    assert bars["rekognition"] is False
    assert bars["rekognition_probe_deadline_ms"] == 1500 and bars["rekognition_timeout_ms"] == 700


@pytest.mark.parametrize("rek", [True, False])
def test_policy_bars_online_follow_the_rekognition_switch(make_rt, rek):
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud)
    cloud.bundle = rt.bundles.lvb
    rt.cfg = rt.cfg.with_overrides({"match": {"rekognition": {"enabled": rek}}})
    bring_online(rt)
    bars = rt.mode_status()["policy_bars"]
    T = rt.cfg.for_mode("ONLINE" if rek else "OFFLINE")  # Rekognition off -> local matcher, OFFLINE bars
    assert bars["rekognition"] is rek and bars["match_allow"] == T.match.local.allow_min_cosine
    assert bars["pad_pass"] == rt.cfg.for_mode("ONLINE").liveness.pad.pass_min


def test_online_demo_clock_rollback_is_a_staff_override_step_up_never_a_crash(make_rt):
    """Lead 2026-11-14: demo clock before issued_at - 300 s while online -> bundle untrusted -> OFFLINE."""
    cloud = FakeCloud(None)
    rt = make_rt(cloud=cloud, DEMO_MODE="1")
    cloud.bundle = rt.bundles.lvb
    bring_online(rt)
    assert rt.mode() == "ONLINE"
    rt.set_demo_clock(offset_s=-3600)
    assert rt.mode_status()["mode"] == "OFFLINE"
    body = ok(rt.decide(attempt("att_rt_rollback")))
    assert body["decision"] == "STEP_UP" and body["mode"] == "OFFLINE"
    assert {"SCHEDULE_BUNDLE_INVALID", "OFFLINE_FALLBACK_REQUIRED", "OFFLINE_MODE"} <= set(body["reason_codes"])
    assert body["next_action"]["methods"] == ["STAFF_OVERRIDE"] and body["schedule_result"] is None
