"""GET /v1/schedule/{kiosk_id} (signed bundle), /v1/revocations, /v1/schedule/check, OTP, Face Liveness, admin."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from cloud.app.canonical import canonical_json, hmac_hex
from cloud.app.clock import parse_ts
from cloud.app.services.schedule_service import verify_bundle
from cloud.tools.fakeimg import make_fake_jpeg

from .conftest import ADMIN, BUNDLE_KEY, T0


def _fresh_code(code: str = "60417223", code_id: str = "OVR-T0001") -> dict:
    import hashlib

    salt = "0f1e2d3c4b5a6978"
    return {"code_id": code_id, "staff_id": "s_guard01", "salt": salt, "valid_until": "2000-01-01T00:00:00Z",
            "hash": hashlib.pbkdf2_hmac("sha256", code.encode(), bytes.fromhex(salt), 100000).hex()}


def test_bundle_is_schedule_example_format_filtered_and_signed(signed, services):
    # the seed's publicly documented OVR-001..003 are stripped; a fresh (non-documented) code is published
    services.schedule.publish(lambda d: d["override_codes"]["codes"].append(_fresh_code()), "test:code")
    r = signed.get("/v1/schedule/KIOSK_LIB_01")
    assert r.status_code == 200 and r.headers["etag"] == '"43"'
    b = r.json()
    from cloud.app.config import PROJECT_ROOT

    example = json.loads((PROJECT_ROOT / "config" / "schedule.example.json").read_text(encoding="utf-8"))
    assert set(b) <= set(example) | {"signature"} and {"zones", "roles", "users", "signature"} <= set(b)
    assert list(b["zones"]) == ["LIBRARY"] and list(b["kiosks"]) == ["KIOSK_LIB_01"]
    assert all(set(r_.get("windows", {})) <= {"LIBRARY"} for r_ in b["roles"].values())
    assert "u_7a8b" in b["users"] and "u_e1f2" not in b["users"]  # visitor pass excludes LIBRARY
    assert "u_a3b4" in b["users"] and b["users"]["u_a3b4"]["revoked"] is True  # revoked users kept
    # lead decision: issued_at = now, expires_at = now + 12 h, override valid_until = expires_at + 24 h
    issued, expires = parse_ts(b["issued_at"]), parse_ts(b["expires_at"])
    assert issued == T0 and expires - issued == timedelta(hours=12)
    assert [c["code_id"] for c in b["override_codes"]["codes"]] == ["OVR-T0001"]
    assert {c["valid_until"] for c in b["override_codes"]["codes"]} == {"2026-11-15T16:35:00Z"}
    # signature = HMAC-SHA256 over canonical JSON of the bundle without `signature`
    sig = b["signature"]
    assert sig["alg"] == "HMAC-SHA256" and sig["key_id"] == "demo-k1"
    body = {k: v for k, v in b.items() if k != "signature"}
    assert sig["value"] == hmac_hex(BUNDLE_KEY, canonical_json(body))
    assert verify_bundle(b, BUNDLE_KEY)
    b["users"]["u_3c4d"]["role"] = "staff"
    assert not verify_bundle(b, BUNDLE_KEY)  # tamper -> invalid


def test_bundle_filtering_is_safe_for_every_kiosk_user_and_half_hour(signed, services):
    """Property: per-kiosk filtering never changes an included user's result and only drops users who
    could not be admitted at that zone (same evaluate_schedule as the edge, all kiosks, one week)."""
    from edge.policy.schedule import evaluate_schedule

    cfg = services.thresholds.raw["schedule"]
    master = services.schedule.doc()
    admit = {"IN_WINDOW", "GRACE_WINDOW"}
    checked = 0
    for kiosk, k in master["kiosks"].items():
        zone = k["zone"]
        b = signed.get(f"/v1/schedule/{kiosk}", kiosk=kiosk).json()
        for step in range(7 * 48):
            t = datetime(2026, 11, 14, 0, 0, tzinfo=UTC) + timedelta(minutes=30 * step)
            for uid in master["users"]:
                expected = evaluate_schedule(uid, zone, t, master, cfg)
                if uid in b["users"]:
                    assert evaluate_schedule(uid, zone, t, b, cfg) == expected, (kiosk, uid, t)
                else:
                    assert expected not in admit, (kiosk, uid, t)
                checked += 1
    assert checked == 5 * 7 * 48 * len(master["users"])
    t = datetime(2026, 11, 14, 17, 40, tzinfo=UTC)  # Sat 23:10 IST: Aarav in hostel grace (SC1.6 #8)
    hostel = signed.get("/v1/schedule/KIOSK_HOSTEL_01", kiosk="KIOSK_HOSTEL_01").json()
    assert evaluate_schedule("u_1a2b", "HOSTEL", t, hostel, cfg) == "GRACE_WINDOW"


def test_bundle_etag_304_and_version_bump(signed, services):
    assert signed.get("/v1/schedule/KIOSK_LIB_01", headers={"If-None-Match": '"42"'}).status_code == 304
    services.schedule.revoke(rtype="USER", target_id="u_1a2b", reason="ADMIN")
    r = signed.get("/v1/schedule/KIOSK_LIB_01", headers={"If-None-Match": '"42"'})
    assert r.status_code == 200 and r.json()["bundle_version"] == 43 and r.headers["etag"] == '"43"'
    assert r.json()["revocations_version"] == 8


def test_bundle_kiosk_must_match_and_exist(signed):
    assert signed.get("/v1/schedule/KIOSK_MAIN_01").status_code == 403  # signed as KIOSK_LIB_01
    r = signed.get("/v1/schedule/KIOSK_NOPE", kiosk="KIOSK_NOPE")
    assert r.status_code == 401  # unknown kiosk cannot even authenticate


def test_revocations_feed_since(signed, services):
    r = signed.get("/v1/revocations?since=0").json()
    assert r["revocation_seq"] == 7 and [i["target_id"] for i in r["items"]] == ["u_a3b4"]
    services.schedule.revoke(rtype="CARD", target_id="d321eef0", reason="LOST")
    r2 = signed.get("/v1/revocations?since=7").json()
    assert r2["revocation_seq"] == 8 and r2["items"][0]["type"] == "CARD"
    assert signed.get("/v1/revocations?since=8").json()["items"] == []


def test_schedule_check_uses_shared_evaluator(signed):
    r = signed.post("/v1/schedule/check", {"user_id": "u_3c4d", "t0": "2026-11-14T10:05:00+05:30"})
    assert r.status_code == 200 and r.json()["result"] == "IN_WINDOW" and r.json()["zone"] == "LIBRARY"
    assert r.json()["evaluator"] == "edge.policy.schedule.evaluate_schedule"
    k = signed.post("/v1/schedule/check", {"user_id": "u_a3b4", "zone": "MAIN_GATE"}).json()
    assert k["result"] == "REVOKED"


# ---------------------------------------------------------------- admin
def test_admin_requires_token_and_revokes(signed, services):
    assert signed.post("/v1/admin/revocations", {"target_id": "u_3c4d"}).status_code == 403
    r = signed.post("/v1/admin/revocations", {"target_id": "u_3c4d", "reason": "SUSPENDED"},
                    headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 201 and r.json()["seq"] == 8 and r.json()["bundle_version"] == 43
    alerts = signed.get("/v1/admin/alerts", headers={"X-Admin-Token": ADMIN})
    assert alerts.status_code == 200


# ---------------------------------------------------------------- OTP
def _enroll(signed):
    body = {"user_id": "u_3c4d", "display_name": "Priya N.", "email": "priya@example.org", "groups": ["student"],
            "consent": True, "consent_version": "v1",
            "images_b64": [base64.b64encode(make_fake_jpeg("u_3c4d")).decode()]}
    assert signed.post("/v1/enroll", body).status_code == 201


def _code(services) -> str:
    body = services.mailer.outbox[-1].body
    return next(tok.strip(".") for tok in body.split() if tok.strip(".").isdigit() and len(tok.strip(".")) == 6)


def test_otp_send_verify_single_use(signed, services):
    _enroll(signed)
    s = signed.post("/v1/otp/send", {"attempt_id": "att_o1", "user_id": "u_3c4d", "channel": "email"})
    assert s.status_code == 201, s.text
    o = s.json()
    assert o["code_length"] == 6 and o["destination_masked"] == "p****@example.org" and o["resend_after_s"] == 30
    assert parse_ts(o["expires_at"]) - T0 == timedelta(seconds=300)
    code = _code(services)
    item = services.kv.get("otp", o["otp_id"])
    assert code not in json.dumps(item)  # only a keyed hash is stored
    bad = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_o1", "code": "000000"
                                         if code != "000000" else "111111"}).json()
    assert bad == {"otp_id": o["otp_id"], "verified": False, "attempts_remaining": 2, "reason": "MISMATCH"}
    ok = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_o1", "code": code}).json()
    assert ok["verified"] is True
    # byte-identical re-send within the same second would be rejected as a replay (401); vary whitespace
    again = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_o1", "code": code + " "}).json()
    assert again["verified"] is False and again["reason"] == "USED"


def test_otp_three_attempts_then_locked_and_expiry(signed, services, clock):
    _enroll(signed)
    o = signed.post("/v1/otp/send", {"attempt_id": "att_o2", "user_id": "u_3c4d"}).json()
    code = _code(services)
    wrong = "123456" if code != "123456" else "654321"
    for left in (2, 1, 0):
        r = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_o2",
                                           "code": wrong + " " * left}).json()
        assert r["attempts_remaining"] == left
    r = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_o2", "code": code}).json()
    assert r["verified"] is False and r["reason"] == "LOCKED"
    clock.advance(seconds=31)
    o3 = signed.post("/v1/otp/send", {"attempt_id": "att_o3", "user_id": "u_3c4d"}).json()
    clock.advance(seconds=301)
    r = signed.post("/v1/otp/verify", {"otp_id": o3["otp_id"], "attempt_id": "att_o3", "code": _code(services)})
    assert r.json()["verified"] is False and r.json()["reason"] in {"EXPIRED", "NOT_FOUND"}


def test_otp_bound_to_attempt_and_resend_rate_limited(signed, services):
    _enroll(signed)
    o = signed.post("/v1/otp/send", {"attempt_id": "att_o4", "user_id": "u_3c4d"}).json()
    r = signed.post("/v1/otp/verify", {"otp_id": o["otp_id"], "attempt_id": "att_other", "code": _code(services)})
    assert r.json()["reason"] == "ATTEMPT_MISMATCH"
    again = signed.post("/v1/otp/send", {"attempt_id": "att_o4", "user_id": "u_3c4d", "channel": "email"})
    assert again.status_code == 429


def test_otp_ses_failure_is_503_so_edge_switches_to_totp(signed, services):
    _enroll(signed)
    services.mailer.fail = True
    r = signed.post("/v1/otp/send", {"attempt_id": "att_o5", "user_id": "u_3c4d"})
    assert r.status_code == 503 and r.json()["error"]["code"] == "CLOUD_UNAVAILABLE"
    assert signed.post("/v1/otp/send", {"attempt_id": "att_o6", "user_id": "u_3c4d",
                                        "channel": "sms"}).status_code == 422


# ---------------------------------------------------------------- Face Liveness (optional)
def test_liveness_session_and_verified_result(signed, services):
    _enroll(signed)
    s = signed.post("/v1/liveness/session", {"attempt_id": "att_l1", "kiosk_id": "KIOSK_LIB_01",
                                             "user_id": "u_3c4d"})
    assert s.status_code == 201 and s.json()["region"] == "us-east-1"
    res = signed.get(f"/v1/liveness/session/{s.json()['session_id']}/result").json()
    assert res["status"] == "SUCCEEDED" and res["live"] and res["verified"] and res["compare_similarity"] >= 99


@pytest.mark.parametrize("confidence,verified", [(79.9, False), (80.0, True)])
def test_liveness_threshold_from_yaml(signed, services, confidence, verified):
    _enroll(signed)
    services.faces.liveness_confidence = confidence
    sid = signed.post("/v1/liveness/session", {"attempt_id": f"att_l{confidence}", "kiosk_id": "KIOSK_LIB_01",
                                               "user_id": "u_3c4d"}).json()["session_id"]
    assert signed.get(f"/v1/liveness/session/{sid}/result").json()["verified"] is verified


def test_liveness_concurrency_cap(signed, services):
    services.liveness.gauge.limit = 1
    body = {"attempt_id": "att_c1", "kiosk_id": "KIOSK_LIB_01", "user_id": "u_3c4d"}
    assert signed.post("/v1/liveness/session", body).status_code == 201
    assert signed.post("/v1/liveness/session", {**body, "attempt_id": "att_c2"}).status_code == 429


def test_admin_contact_enables_otp_without_faces(signed, services):
    r = signed.request("PUT", "/v1/admin/users/u_prj1/contact", json_body={
        "display_name": "Prajwal M.", "email": "operator@example.org", "consent": True, "consent_version": "v1"},
        headers={"X-Admin-Token": ADMIN})
    assert r.status_code == 200, r.text
    assert r.json() == {"user_id": "u_prj1", "destination_masked": "o*******@example.org", "faces_enrolled": 0}
    o = signed.post("/v1/otp/send", {"attempt_id": "att_c1", "user_id": "u_prj1"})
    assert o.status_code == 201 and services.mailer.outbox[-1].to == "operator@example.org"
    assert signed.request("PUT", "/v1/admin/users/u_prj1/contact", json_body={
        "display_name": "x", "email": "a@b.co", "consent": True, "consent_version": "v1"}).status_code == 403


@pytest.mark.parametrize("length,status", [(40, 200), (41, 422)])
def test_admin_contact_consent_version_max_40_like_enroll_meta(signed, length, status):
    """consent_version is 1-40 characters on every route that takes it (EnrollMeta, edge schemas.py)."""
    r = signed.request("PUT", "/v1/admin/users/u_prj1/contact", json_body={
        "display_name": "Prajwal M.", "email": "operator@example.org", "consent": True,
        "consent_version": "v" * length}, headers={"X-Admin-Token": ADMIN})
    assert r.status_code == status, r.text


def test_consent_version_limit_matches_enroll_meta():
    from cloud.app import schemas as S

    def max_len(model):
        return next(m.max_length for m in model.model_fields["consent_version"].metadata
                    if getattr(m, "max_length", None) is not None)

    assert max_len(S.AdminContactRequest) == max_len(S.EnrollMeta) == 40


def test_admin_contact_display_name_is_trimmed_r_h(signed, services):
    def put(name: str):
        return signed.request("PUT", "/v1/admin/users/u_prj1/contact", json_body={
            "display_name": name, "email": "operator@example.org", "consent": True, "consent_version": "v1"},
            headers={"X-Admin-Token": ADMIN})

    assert put("   ").status_code == 422
    assert put("  Prajwal M.  ").status_code == 200
    assert services.kv.get("users", "u_prj1")["display_name"] == "Prajwal M."


def test_demo_seed_recomputes_placeholder_card_hashes(clock):
    import hashlib
    import hmac as _h

    from cloud.app.config import PROJECT_ROOT
    from cloud.app.container import build_services

    from .conftest import make_settings

    svc = build_services(make_settings(seed_schedule_path=str(PROJECT_ROOT / "config" / "schedule.demo.json")),
                         clock=clock)
    assert svc.schedule.ensure_seeded()
    users = svc.schedule.doc()["users"]
    want = _h.new(b"hidhack-demo-pepper", b"HID-DEMO-0001", hashlib.sha256).hexdigest()
    assert users["u_prj1"]["fallback"]["card_id_hash"] == want
    assert not any("RECOMPUTED" in str(u.get("fallback")) for u in users.values())


def test_relative_seed_path_resolves_against_project_root():
    from cloud.app.config import PROJECT_ROOT, _path

    assert _path("config/schedule.demo.json", PROJECT_ROOT / "x") == str(PROJECT_ROOT / "config" / "schedule.demo.json")
    assert _path("", PROJECT_ROOT / "x") == str(PROJECT_ROOT / "x")
