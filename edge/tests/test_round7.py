"""Round 7 (v1.4 admin-access contract, lead rulings R-A..R-H), end to end on a scratch app + FAKE cloud:

R-A  register a NEW person: PUT access {display, role, consent} creates the schedule entry and installs the
     re-signed bundle in the same call, THEN POST /v1/enroll works with the chosen role (faculty stays faculty).
     Offline: new people are refused (503 OFFLINE); people already in the bundle still enrol (skipped_offline).
R-B  erase -> re-register: 409 ERASED_IN_BUNDLE until the PUT with consent re-admits, then enrolment works.
R-C  revoke -> SCHEDULE_REVOKED view at once; Restore = PUT consent + restore.
R-F  cloud enrol failure / offline: cloud_state + warnings; TOTP not active -> warning.
R-G  the challenge nonce is released on ANY failure before a decision is produced.
R-H  one set of field limits.
Never the real cloud, never the live :8000.
"""

from __future__ import annotations

import json

import pytest

from edge.tests.conftest import requires_models
from edge.tests.contract_cloud import ADMIN, Env, _face_frames

META = {"consent": True, "consent_version": "2026-11-14.v1"}


def _enrol(env: Env, uid: str, display: str = "Synthetic", **extra):
    files = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(_face_frames())}
    meta = {"user_id": uid, "display_name": display, **META, **extra}
    return env.c.post("/v1/enroll", files=files, data={"meta": json.dumps(meta)}, headers=ADMIN)


def _users(env: Env) -> dict[str, dict]:
    body = env.c.get("/v1/admin/access/users", headers=ADMIN).json()
    return {u["user_id"]: u for u in body["users"]}


# ---------------------------------------------------------------- R-A
@requires_models
def test_register_new_faculty_puts_access_first_then_enrols_as_faculty(make_env):
    env = make_env(models=True)
    first = _enrol(env, "u_kv02", "Prof. Arjun T.")
    assert first.status_code == 409 and first.json()["error"]["reason"] == "NOT_IN_SCHEDULE"  # the old bug's cause
    put = env.put("u_kv02", {"display": "Prof. Arjun T.", "role": "faculty", "consent": True, "actor": "register"})
    assert put["created"] and put["bundle"]["applied"] and put["user"]["in_bundle"], put
    assert env.ctx.runtime.user_info("u_kv02")["role"] == "faculty"  # applies to the very next decision
    r = _enrol(env, "u_kv02", "Prof. Arjun T.")
    assert r.status_code == 201, r.text
    e = r.json()
    assert e["schedule_role"] == "faculty" and e["role_requested"] is None and e["warnings"] == []
    assert e["cloud_state"] == "indexed" and e["totp_active"] is True
    users = env.c.get("/v1/admin/users", headers=ADMIN).json()["users"]
    assert next(u for u in users if u["user_id"] == "u_kv02")["role"] == "faculty"
    sent = env.cloud.calls("PUT", "/v1/admin/users/u_kv02/access")[-1]
    assert sent["json"] == {"display": "Prof. Arjun T.", "role": "faculty", "consent": True, "actor": "register"}
    assert sent["headers"]["x-admin-token"] and sent["headers"]["x-signature"]


@requires_models
def test_offline_new_person_is_refused_but_a_bundle_user_still_enrols(make_env):
    env = make_env(models=True)
    env.force_offline()
    r = env.c.put("/v1/admin/access/users/u_kv02", json={"display": "X", "role": "faculty", "consent": True},
                  headers=ADMIN)
    assert r.status_code == 503 and r.json()["error"]["reason"] == "OFFLINE"
    assert not env.cloud.calls("PUT", "/v1/admin/users/")
    ok = _enrol(env, "u_3c4d", "Priya N.")
    assert ok.status_code == 201 and ok.json()["cloud_state"] == "skipped_offline"
    assert any("OFFLINE" in w for w in ok.json()["warnings"])


def test_role_pre_check_and_bundle_stale_mode_allows_writes(make_env):
    env = make_env()
    r = env.c.put("/v1/admin/access/users/u_kv02", json={"display": "X", "role": "dean", "consent": True},
                  headers=ADMIN)
    assert r.status_code == 422 and r.json()["error"]["reason"] == "UNKNOWN_ROLE"
    assert not env.cloud.calls("PUT", "/v1/admin/users/")  # validation order: pre-check before the cloud
    # LIBRARY is not in this MAIN_GATE bundle, but zones are the cloud's call (forwarded, accepted)
    ok = env.put("u_3c4d", {"role": "student", "zones_add": ["LIBRARY"]})
    assert ok["bundle"]["applied"] and env.cloud.master["users"]["u_3c4d"]["zones_add"] == ["LIBRARY"]


# ---------------------------------------------------------------- R-B / R-C
@requires_models
def test_erase_then_readmit_and_enrol_again(make_env):
    env = make_env(models=True)
    assert _enrol(env, "u_3c4d", "Priya N.").status_code == 201
    d = env.c.delete("/v1/enroll/u_3c4d", headers=ADMIN).json()
    assert d["cloud"] == "deleted" and d["local_removed"] and d["bundle"]["result"] == "installed"
    assert env.ctx.templates.get("u_3c4d") is None
    assert _users(env)["u_3c4d"]["status"] == "ERASED"
    blocked = _enrol(env, "u_3c4d", "Priya N.")
    assert blocked.status_code == 409 and blocked.json()["error"]["reason"] == "ERASED_IN_BUNDLE"
    no_consent = env.c.put("/v1/admin/access/users/u_3c4d", json={"role": "student"}, headers=ADMIN)
    assert no_consent.status_code == 409 and no_consent.json()["error"]["reason"] == "ERASED_IN_BUNDLE"
    put = env.put("u_3c4d", {"display": "Priya N.", "role": "student", "consent": True, "actor": "register"})
    assert put["readmitted"] and put["user"]["status"] == "ACTIVE" and put["bundle"]["applied"]
    again = _enrol(env, "u_3c4d", "Priya N.")
    assert again.status_code == 201, again.text
    assert "u_3c4d" in env.ctx.runtime.entitled_user_ids()  # the gallery admits them again


def test_revoke_then_restore(make_env):
    env = make_env()
    r = env.c.post("/v1/admin/access/users/u_3c4d/revoke", json={"reason": "LOST_BADGE", "actor": "cp"},
                   headers=ADMIN)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["user"]["status"] == "REVOKED" and out["user"]["today"]["status_now"] == "REVOKED"
    assert env.cloud.calls("POST", "/v1/admin/revocations")[-1]["json"] == {
        "type": "USER", "target_id": "u_3c4d", "reason": "LOST_BADGE", "actor": "cp"}
    again = env.c.post("/v1/admin/access/users/u_3c4d/revoke", headers=ADMIN)
    assert again.status_code == 409 and again.json()["error"]["reason"] == "ALREADY_REVOKED"
    reg = env.c.put("/v1/admin/access/users/u_3c4d", json={"role": "student", "consent": True}, headers=ADMIN)
    assert reg.status_code == 409 and reg.json()["error"]["reason"] == "USER_REVOKED"
    restored = env.put("u_3c4d", {"role": "student", "consent": True, "restore": True})
    assert restored["restored"] and restored["user"]["status"] == "ACTIVE"
    assert restored["user"]["today"]["status_now"] == "IN_WINDOW"


# ---------------------------------------------------------------- R-F
@requires_models
def test_cloud_enrol_failure_is_flagged_and_totp_is_not_active(make_env):
    env = make_env(models=True)
    env.put("u_kv02", {"display": "Prof. Arjun T.", "role": "faculty", "consent": True})
    env.cloud.fail[("POST", "/v1/enroll")] = (503, {"error": {"code": "CLOUD_UNAVAILABLE", "message": "x"}}, {})
    e = _enrol(env, "u_kv02", "Prof. Arjun T.").json()
    assert e["cloud_state"] == "failed" and e["cloud_indexed"] is False and e["totp_active"] is False
    assert any("NOT indexed" in w for w in e["warnings"]) and any("TOTP is not active" in w for w in e["warnings"])


@requires_models
def test_legacy_meta_role_is_ignored_with_a_warning(make_env):
    env = make_env(models=True)
    e = _enrol(env, "u_5e6f", "Dr. Meera I.", role="student").json()
    assert e["schedule_role"] == "faculty" and e["role_requested"] == "student" and e["role_applied"] is False
    assert any("NOT applied" in w for w in e["warnings"])
    assert env.ctx.templates.get("u_5e6f").role == "faculty"


# ---------------------------------------------------------------- R-G
def _challenge_attempt(ctx):
    att = ctx.sessions.create(kiosk_id="KIOSK_MAIN_01", flash_enabled=False, flash_sequence=[], camera_label="cam",
                              claimed_user_id=None, recapture_of=None, recapture_count=0)
    att.candidate_user_id = "u_3c4d"
    att.last_response = {"attempt_id": att.attempt_id, "decision": "STEP_UP",
                         "next_action": {"type": "CHALLENGE", "challenge": {"challenge_id": "chl_0123456789ab"}}}
    return att


def _challenge(env: Env, att, nonce: str = "nonce-abcdefghijklmnop"):
    meta = {"challenge_id": "chl_0123456789ab", "nonce": nonce, "same_track": True,
            "actions": [{"action": "SMILE", "prompted_at_ms": 1, "baseline": 0.1, "peak": 0.8}]}
    return env.c.post(f"/v1/attempt/{att.attempt_id}/challenge", json=meta)


def test_challenge_nonce_is_released_on_any_failure_before_a_decision(make_env, monkeypatch):
    from edge import attempts
    from edge.errors import ApiError

    env = make_env()
    att = _challenge_attempt(env.ctx)
    real = attempts.process_challenge
    failures = [ApiError("CLOUD_UNAVAILABLE", "runtime busy"), RuntimeError("depth bridge crashed")]

    async def flaky(ctx, a, meta, jpeg):
        if failures:
            raise failures.pop(0)
        return await real(ctx, a, meta, jpeg)

    monkeypatch.setattr(attempts, "process_challenge", flaky)
    r1 = _challenge(env, att)
    assert r1.status_code == 503  # not a VALIDATION_ERROR: before v1.4 the nonce stayed burned
    with pytest.raises(RuntimeError):
        _challenge(env, att)
    assert "nonce-abcdefghijklmnop" not in att.challenge_nonces
    monkeypatch.setattr(env.ctx.runtime, "resolve_challenge", lambda aid, ev: {
        "attempt_id": aid, "decision": "DENY", "reason_codes": ["CHALLENGE_FAILED"], "mode": "ONLINE"})
    ok = _challenge(env, att)
    assert ok.status_code == 200 and ok.json()["decision"] == "DENY"
    assert "nonce-abcdefghijklmnop" in att.decided_challenge_nonces


# ---------------------------------------------------------------- R-H
@pytest.mark.parametrize(("path", "body"), [
    ("/v1/admin/access/users/u_3c4d", {"role": "student", "display": "x" * 81}),
    ("/v1/admin/access/users/u_3c4d", {"role": "student", "display": "  "}),
    ("/v1/admin/access/users/u_3c4d", {"role": "student", "zones_add": ["Z"] * 17}),
    ("/v1/admin/access/users/u_3c4d", {"role": "student", "extra_windows": {
        "MAIN_GATE": [{"days": ["MON"], "start": "09:00", "end": "10:00"}] * 15}}),
    ("/v1/admin/access/users/u_3c4d", {"role": "student", "valid_from": "2026-11-15T00:00:00"}),
    ("/v1/admin/access/users/U_3C4D", {"role": "student"}),
])
def test_field_limits_are_enforced_before_any_cloud_call(make_env, path, body):
    env = make_env()
    r = env.c.put(path, json=body, headers=ADMIN)
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR", r.text
    assert not env.cloud.calls("PUT", "/v1/admin/users/")


def test_valid_until_is_forwarded_and_shown_in_utc(make_env):
    env = make_env()
    out = env.put("u_9c0d", {"role": "contractor", "valid_until": "2026-12-15T23:59:00+05:30"})
    assert env.cloud.calls("PUT", "/v1/admin/users/u_9c0d/access")[-1]["json"]["valid_until"] == "2026-12-15T18:29:00Z"
    assert out["user"]["valid_until"] == "2026-12-15T18:29:00Z"
