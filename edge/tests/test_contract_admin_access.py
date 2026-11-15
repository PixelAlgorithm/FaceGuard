"""Contract test: docs/contracts/admin_access.examples.json (API v1.4, canonical) vs the edge.

1. Models: every edge example's request validates against the edge request model (or is rejected by it, for
   errors with request_invalid=true); every 2xx example body parses into the edge response model with no field
   lost or invented (the response models are extra="forbid"); every error reason is in the registry.
2. Handlers: EVERY edge example (valid and error) is replayed against a scratch edge app wired to a
   contract-shaped FAKE cloud (edge/tests/contract_cloud.py; never the real cloud, never the live :8000). Errors
   compare status, error.code and error.reason only (how_to_test); valid replays validate the handler's body
   against the same strict model and compare the normative fields. A new example without a replay spec fails.
Hermetic and clock-independent: the policy runtime uses conftest.TEST_CLOCK (fixed 11:00 IST start).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from edge.access_models import (
    USER_ID,
    AccessUpdate,
    AccessUpdateResult,
    AccessUsersResponse,
    AdminUsersResponse,
    BundleRefresh,
    CodesRotateRequest,
    DemoClock,
    EraseResponse,
    RevokeRequest,
    RevokeResult,
    RotateCodesResult,
)
from edge.config import PROJECT_ROOT
from edge.schemas import ClockRequest, EnrollMeta, EnrollResponse
from edge.tests.contract_cloud import ADMIN, EDGE_ADMIN, Env, _blank_frames, _face_frames

CONTRACT = json.loads((PROJECT_ROOT / "docs" / "contracts" / "admin_access.examples.json").read_text("utf-8"))
EDGE = {r["id"]: r for r in CONTRACT["routes"] if r["side"] == "edge"}

REQUEST_MODEL: dict[str, type[BaseModel]] = {
    "edge.access.users.put": AccessUpdate, "edge.access.users.revoke": RevokeRequest,
    "edge.access.codes.rotate": CodesRotateRequest, "edge.admin.clock.post": ClockRequest,
}
RESPONSE_MODEL: dict[str, type[BaseModel]] = {
    "edge.access.users.list": AccessUsersResponse, "edge.access.users.put": AccessUpdateResult,
    "edge.access.users.revoke": RevokeResult, "edge.access.codes.rotate": RotateCodesResult,
    "edge.bundle.refresh": BundleRefresh, "edge.enroll.post": EnrollResponse, "edge.enroll.delete": EraseResponse,
    "edge.admin.users.list": AdminUsersResponse, "edge.admin.clock.post": DemoClock,
}


def _params(kind: str):
    for rid, r in EDGE.items():
        for ex in r["examples" if kind == "valid" else "errors"]:
            yield pytest.param(rid, ex, id=f"{rid}:{ex['name']}")


def validate_request(rid: str, req: dict[str, Any]) -> None:
    """Raises ValidationError / ValueError when the edge request model (path, body or meta) rejects it."""
    for k, v in (req.get("path_params") or {}).items():
        if k == "user_id" and not re.fullmatch(USER_ID, str(v)):
            raise ValueError(f"path user_id {v!r} does not match {USER_ID}")
    if rid == "edge.enroll.post":
        EnrollMeta.model_validate(req["meta"])
        return
    model = REQUEST_MODEL.get(rid)
    if model is not None and req.get("body") is not None:
        model.model_validate(req["body"])


# ================================================================== 1. models
def test_the_contract_covers_exactly_the_edge_routes_we_serve():
    assert CONTRACT["api_version"] == "v1.4"
    assert set(EDGE) == {"edge.access.users.list", "edge.access.users.put", "edge.access.users.revoke",
                         "edge.access.codes.rotate", "edge.bundle.refresh", "edge.enroll.post",
                         "edge.enroll.delete", "edge.admin.users.list", "edge.mode.get", "edge.admin.clock.post"}
    from edge.app import router

    paths = {(m, r.path) for r in router.routes for m in getattr(r, "methods", ()) or ()}
    for r in EDGE.values():
        assert (r["method"], r["path"]) in paths, r["id"]


@pytest.mark.parametrize(("rid", "ex"), list(_params("valid")))
def test_valid_example_matches_the_edge_models(rid, ex):
    validate_request(rid, ex["request"])
    resp = ex["response"]
    assert 200 <= resp["status"] < 300
    if rid == "edge.mode.get":
        dc = resp["body"]["demo_clock"]
        assert dc is None or DemoClock.model_validate(dc)
        return
    RESPONSE_MODEL[rid].model_validate(resp["body"])
    if rid == "edge.access.codes.rotate":
        assert resp["headers"]["Cache-Control"] == "no-store"


@pytest.mark.parametrize(("rid", "ex"), list(_params("error")))
def test_error_example_matches_the_edge_models(rid, ex):
    if ex["request_invalid"]:
        with pytest.raises((ValidationError, ValueError)):
            validate_request(rid, ex["request"])
    else:
        validate_request(rid, ex["request"])
    err = ex["response"]["body"]["error"]
    assert err["attempt_id"] is None and err["code"] and err["message"]
    reason = err.get("reason")
    if reason is not None:
        reg = CONTRACT["error_reasons"][reason]
        statuses = reg["status"] if isinstance(reg["status"], list) else [reg["status"]]
        codes = reg["code"] if isinstance(reg["code"], list) else [reg["code"]]
        assert ex["response"]["status"] in statuses and err["code"] in codes


# ================================================================== 2. handlers (scratch app + fake cloud)
def send(env: Env, rid: str, req: dict[str, Any], *, body: Any = ..., frames: list[bytes] | None = None):
    route = EDGE[rid]
    path = route["path"].format(**(req.get("path_params") or {}))
    headers = {k: (EDGE_ADMIN if v == "<ADMIN_TOKEN>" else v) for k, v in (req.get("headers") or {}).items()}
    body = req.get("body") if body is ... else body
    kw: dict[str, Any] = {"headers": headers, "params": req.get("query") or None}
    if req.get("content_type") == "multipart/form-data":
        jp = frames if frames is not None else _face_frames()[: int(req.get("frames") or 5)]
        kw["files"] = {f"frame_{i}": (f"f{i}.jpg", b, "image/jpeg") for i, b in enumerate(jp)}
        kw["data"] = {"meta": json.dumps(req["meta"])}
    elif body is not None:
        kw["json"] = body
    return env.c.request(route["method"], path, **kw)


def _get(d: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if d is None:
            return None
        d = d[int(part)] if isinstance(d, list) else d.get(part)
    return d


# ---------------------------------------------------------------- error replays
CLOUD_ROUTE = {"edge.access.users.put": ("PUT", "/v1/admin/users/"),
               "edge.access.users.revoke": ("POST", "/v1/admin/revocations"),
               "edge.access.codes.rotate": ("POST", "/v1/admin/codes/rotate")}


def inject_cloud_error(env: Env, rid: str, ex: dict[str, Any]) -> None:
    """Make the fake cloud answer the way the example's state says (cloud_status / cloud_code / reason)."""
    err = ex["response"]["body"]["error"]
    status, reason = err["cloud_status"], err.get("reason")
    if reason == "ENDPOINT_NOT_DEPLOYED":
        body = {"error": {"code": "NOT_FOUND", "message": "Not Found"}}
    elif reason == "CLOUD_ADMIN_TOKEN":
        body = {"error": {"code": "FORBIDDEN", "message": "admin token required (X-Admin-Token)"}}
    elif reason == "CLOUD_ERROR":
        body = {"error": {"code": "INTERNAL", "message": "upstream failed"}}
    else:
        body = {"error": {"code": err.get("cloud_code") or err["code"],
                          "message": err["message"].removeprefix("cloud: "), "reason": reason}}
    env.cloud.fail[CLOUD_ROUTE[rid]] = (status, body, {})


def _create(uid: str, display: str = "Prof. Arjun T.", role: str = "faculty") -> Callable[[Env], None]:
    return lambda env: env.put(uid, {"display": display, "role": role, "consent": True, "actor": "register"})


def _no_bundle(env: Env) -> None:
    env.ctx.runtime.bundles._lvb = None


def _face_other(env: Env) -> None:
    _create("u_kv02")(env)
    r = send(env, "edge.enroll.post", {"headers": {"X-Admin-Token": "<ADMIN_TOKEN>"},
                                      "content_type": "multipart/form-data", "frames": 5,
                                      "meta": {"user_id": "u_3c4d", "display_name": "Priya N.", "consent": True,
                                               "consent_version": "2026-11-14.v1"}})
    assert r.status_code == 201, r.text


def _look_mismatch(env: Env, monkeypatch) -> None:
    r = send(env, "edge.enroll.post", {"headers": {"X-Admin-Token": "<ADMIN_TOKEN>"},
                                      "content_type": "multipart/form-data", "frames": 5,
                                      "meta": {"user_id": "u_3c4d", "display_name": "Priya N.", "consent": True,
                                               "consent_version": "2026-11-14.v1"}})
    assert r.status_code == 201, r.text
    monkeypatch.setattr("edge.enroll.resemblance_to_stored", lambda *_a, **_k: 0.312)


def _templates_gone(env: Env) -> None:
    env.ctx.templates = None


# (route id, example name) -> {app: builder kwargs, prep: fn(env[, monkeypatch]), frames: factory, inject: bool}
ERROR_SPECS: dict[tuple[str, str], dict[str, Any]] = {
    ("edge.access.users.list", "no_admin_token"): {},
    ("edge.access.users.put", "no_admin_token"): {},
    ("edge.access.users.put", "offline"): {"prep": Env.force_offline},
    ("edge.access.users.put", "cloud_not_configured"): {"app": {"cloud_on": False}},
    ("edge.access.users.put", "cloud_transport_error"): {"inject": True},
    ("edge.access.users.put", "endpoint_not_deployed"): {"inject": True},
    ("edge.access.users.put", "cloud_refused_admin_token"): {"inject": True},
    ("edge.access.users.put", "unknown_role"): {},
    ("edge.access.users.put", "unknown_zone"): {"inject": True, "natural": True},
    ("edge.access.users.put", "create_without_consent"): {"inject": True, "natural": True},
    ("edge.access.users.put", "create_without_display"): {"inject": True, "natural": True},
    ("edge.access.users.put", "erased_without_consent"): {"inject": True, "natural": True},
    ("edge.access.users.put", "revoked_register_without_restore"): {"inject": True, "natural": True},
    ("edge.access.users.put", "schedule_conflict"): {"inject": True},
    ("edge.access.users.revoke", "offline"): {"prep": Env.force_offline},
    ("edge.access.users.revoke", "unknown_user"): {"inject": True, "natural": True},
    ("edge.access.users.revoke", "already_revoked"): {"inject": True, "natural": True},
    ("edge.access.codes.rotate", "offline"): {"prep": Env.force_offline},
    ("edge.access.codes.rotate", "cloud_cannot_mint"): {"inject": True},
    ("edge.bundle.refresh", "forced_offline"): {"prep": Env.force_offline},
    ("edge.bundle.refresh", "not_configured"): {"app": {"cloud_on": False}},
    ("edge.bundle.refresh", "cloud_error"): {"prep": lambda env: setattr(env.cloud, "down", True)},
    ("edge.bundle.refresh", "bundle_rejected"): {
        "prep": lambda env: (setattr(env.cloud, "bad_signature", True), env.cloud.publish())},
    ("edge.enroll.post", "not_in_schedule"): {},
    ("edge.enroll.post", "erased_in_bundle"): {},
    ("edge.enroll.post", "no_bundle"): {"prep": _no_bundle},
    ("edge.enroll.post", "revoked"): {},
    ("edge.enroll.post", "face_enrolled_other"): {"app": {"models": True}, "prep": _face_other},
    ("edge.enroll.post", "look_mismatch"): {"app": {"models": True}, "prep_mp": _look_mismatch},
    ("edge.enroll.post", "frames_rejected"): {"app": {"models": True}, "prep": _create("u_kv02"),
                                              "frames": _blank_frames},
    ("edge.enroll.post", "models_unavailable"): {"prep": _create("u_kv02")},
    ("edge.enroll.delete", "not_enrolled"): {"app": {"cloud_on": False}},
    ("edge.admin.users.list", "no_admin_token"): {},
    ("edge.admin.users.list", "cache_unavailable"): {"prep": _templates_gone},
    ("edge.admin.clock.post", "not_demo_mode"): {"app": {"demo": False}},
}


def _error_cases():
    for rid, r in EDGE.items():
        for ex in r["errors"]:
            spec = ERROR_SPECS.get((rid, ex["name"]), {}) if not ex["request_invalid"] else {}
            yield pytest.param(rid, ex, spec, False, id=f"{rid}:{ex['name']}")
            if spec.get("natural"):
                yield pytest.param(rid, ex, spec, True, id=f"{rid}:{ex['name']}:natural-cloud")


def test_every_state_error_example_has_a_replay_spec():
    state = {(rid, ex["name"]) for rid, r in EDGE.items() for ex in r["errors"] if not ex["request_invalid"]}
    assert state == set(ERROR_SPECS), {"missing": state - set(ERROR_SPECS), "stale": set(ERROR_SPECS) - state}


@pytest.mark.parametrize(("rid", "ex", "spec", "natural"), list(_error_cases()))
def test_error_example_replays_through_the_handler(make_env, monkeypatch, rid, ex, spec, natural):
    env = make_env(**spec.get("app", {}))
    if spec.get("prep"):
        spec["prep"](env)
    if spec.get("prep_mp"):
        spec["prep_mp"](env, monkeypatch)
    if spec.get("inject") and not natural:
        inject_cloud_error(env, rid, ex)
    frames = spec["frames"]() if spec.get("frames") else None
    r = send(env, rid, ex["request"], frames=frames)
    want = ex["response"]["body"]["error"]
    got = r.json().get("error") or {}
    assert (r.status_code, got.get("code"), got.get("reason")) == \
        (ex["response"]["status"], want["code"], want.get("reason")), r.text
    assert got.get("attempt_id", "missing") is None and got.get("message")
    for k in ("installed_version", "bundle_version"):  # documented extra keys are present when the example has them
        if k in want:
            assert k in got, (k, r.text)


# ---------------------------------------------------------------- valid replays
PUT_KEYS = ["created", "unchanged", "readmitted", "restored", "previous_role", "role", "bundle.result",
            "bundle.applied", "user.in_bundle", "user.in_schedule", "user.status", "user.role", "user.bundle_role",
            "user.extra_windows", "user.valid_until", "user.zones_add", "user.today.zone"]
ENROLL_KEYS = ["cloud_state", "cloud_indexed", "schedule_role", "role_requested", "role_applied", "totp_active",
               "local_cache_updated"]


def _clock(t: str) -> Callable[[Env], None]:
    def prep(env: Env) -> None:
        assert env.c.post("/v1/admin/clock", json={"set_local": t}, headers=ADMIN).status_code == 200
    return prep


def _stale(env: Env) -> None:
    env.cloud.freeze_bundle()


def _offline_with_totp(env: Env) -> None:
    env.ctx.runtime.provision_totp("u_3c4d")
    env.force_offline()


def _enrol_fail(env: Env) -> None:
    _create("u_kv02")(env)
    env.cloud.fail[("POST", "/v1/enroll")] = (503, {"error": {"code": "CLOUD_UNAVAILABLE",
                                                              "message": "rekognition denied"}}, {})


def _readmit_prj1(env: Env) -> None:
    out = env.put("u_prj1", {"display": "Prajwal M.", "role": "student", "consent": True, "actor": "register"})
    assert out["readmitted"] and out["bundle"]["applied"] and out["user"]["in_bundle"], out


def _version_unknown(route: tuple[str, str], reply: dict[str, Any]) -> Callable[[Env], None]:
    """M2: the cloud accepts the write but its reply has no bundle_version, and the follow-up pull fails."""
    def prep(env: Env) -> None:
        env.cloud.fail[route] = (200, reply, {})
        env.cloud.fail[("GET", f"/v1/schedule/{env.cloud.kiosk}")] = (
            503, {"error": {"code": "INTERNAL", "message": "down"}}, {})
    return prep


def _erase_queue_broken(env: Env) -> None:
    """M1: OFFLINE and the local erasure queue cannot be written (disk error)."""
    env.seed_template("u_tm04")
    env.force_offline()

    def disk_error(_uid: str) -> None:
        raise OSError("disk full")

    env.ctx.runtime.queue_cloud_erasure = disk_error


VALID_SPECS: dict[tuple[str, str], dict[str, Any]] = {
    ("edge.access.users.list", "online_cloud_and_bundle"): {
        "keys": ["source", "read_only", "read_only_code", "mode", "kiosk_id", "zone", "roles", "staff_ids"]},
    ("edge.access.users.list", "offline_bundle_only_read_only"): {
        "prep": Env.force_offline, "keys": ["source", "read_only", "read_only_code", "mode", "cloud_bundle_version"]},
    ("edge.access.users.put", "create_new_faculty_register_step1"): {"keys": PUT_KEYS},
    ("edge.access.users.put", "edit_extra_hours_and_validity"): {"keys": PUT_KEYS + ["user.today.windows"]},
    ("edge.access.users.put", "role_change"): {"keys": PUT_KEYS},
    ("edge.access.users.put", "readmit_erased_user"): {"keys": PUT_KEYS},
    ("edge.access.users.put", "restore_revoked_user"): {"keys": PUT_KEYS},
    ("edge.access.users.put", "unchanged"): {"keys": PUT_KEYS},
    ("edge.access.users.put", "edit_revoked_user_without_restore"): {"keys": PUT_KEYS + ["warnings"]},
    ("edge.access.users.put", "saved_but_not_installed"): {"prep": _stale, "keys": PUT_KEYS + ["user"]},
    ("edge.access.users.put", "created_but_no_access_at_this_kiosk"): {"keys": PUT_KEYS + ["user.today"]},
    ("edge.access.users.put", "saved_version_unknown"): {
        "prep": _version_unknown(("PUT", "/v1/admin/users/"), {"user_id": "u_kv02", "created": True,
                                                               "role": "faculty"}),
        "keys": ["created", "role", "cloud_bundle_version", "bundle.result", "bundle.applied", "user",
                 "warnings.0"]},
    ("edge.access.users.revoke", "revoked_but_not_installed"): {
        "prep": _version_unknown(("POST", "/v1/admin/revocations"), {"type": "USER", "target_id": "u_3c4d",
                                                                    "reason": "ADMIN"}),
        "keys": ["type", "reason", "revoked_at", "seq", "cloud_bundle_version", "bundle.result", "bundle.applied",
                 "user.status", "user.revoked_at", "warnings.0"]},
    ("edge.access.codes.rotate", "minted_version_unknown"): {
        "prep": _version_unknown(("POST", "/v1/admin/codes/rotate"), {
            "staff_id": "s_guard01", "code_length": 8, "codes": [{"code_id": "c1", "code": "40718325"},
                                                                 {"code_id": "c2", "code": "93360142"}]}),
        "keys": ["staff_id", "one_time", "cloud_bundle_version", "bundle.result", "bundle.applied", "warnings.0"],
        "codes": True},
    # R-K: the cloud reply omits code_id / code_length / valid_until (and bundle_version): 200, nulls, codes kept
    ("edge.access.codes.rotate", "minted_fields_unknown"): {
        "prep": _version_unknown(("POST", "/v1/admin/codes/rotate"), {
            "staff_id": "s_guard01", "codes": [{"code": "40718325"}, {"code": "93360142"}],
            "dropped_code_ids": ["OVR-R1114092210-01"]}),
        "keys": ["staff_id", "one_time", "code_length", "valid_until", "codes.0.code_id", "codes.1.code_id",
                 "dropped_code_ids", "cloud_bundle_version", "bundle.result", "bundle.applied", "warnings.0"],
        "codes": "null_ids"},
    ("edge.access.users.revoke", "revoke_admin"): {
        "keys": ["type", "reason", "bundle.result", "bundle.applied", "user.status", "user.revoked_reason",
                 "user.today.status_now"]},
    ("edge.access.users.revoke", "revoke_no_body"): {
        "keys": ["type", "reason", "bundle.applied", "user.status", "user.today.status_now"]},
    ("edge.access.codes.rotate", "rotate_default_count"): {
        "keys": ["staff_id", "code_length", "one_time", "bundle.applied"], "codes": True},
    ("edge.access.codes.rotate", "rotate_minimal_body_keep_existing"): {
        "keys": ["staff_id", "one_time", "dropped_code_ids", "bundle.applied"], "codes": True},
    ("edge.access.codes.rotate", "minted_but_not_installed"): {
        "prep": _stale, "keys": ["staff_id", "one_time", "bundle.result", "bundle.applied"], "codes": True},
    ("edge.bundle.refresh", "installed"): {"prep": lambda env: env.cloud.publish(),
                                           "keys": ["changed", "result", "error"]},
    ("edge.bundle.refresh", "not_modified"): {"keys": ["changed", "result", "error"]},
    ("edge.enroll.post", "online_indexed_new_faculty"): {"app": {"models": True}, "prep": _create("u_kv02"),
                                                         "keys": ENROLL_KEYS + ["warnings"]},
    ("edge.enroll.post", "online_cloud_failed"): {"app": {"models": True}, "prep": _enrol_fail,
                                                  "keys": ENROLL_KEYS},
    ("edge.enroll.post", "offline_existing_bundle_user"): {"app": {"models": True}, "prep": _offline_with_totp,
                                                           "keys": ENROLL_KEYS + ["cloud", "totp_provisioning_uri"]},
    ("edge.enroll.post", "online_after_readmit"): {"app": {"models": True}, "prep": _readmit_prj1,
                                                   "keys": ENROLL_KEYS + ["warnings"]},
    ("edge.enroll.post", "legacy_role_field_ignored"): {"app": {"models": True}, "prep": _create("u_kv02"),
                                                        "keys": ENROLL_KEYS},
    ("edge.enroll.delete", "erased_local_and_cloud"): {
        "prep": lambda env: env.seed_template("u_prj1"),
        "keys": ["local_removed", "cloud", "cloud_status", "message", "bundle.result", "bundle.error"]},
    ("edge.enroll.delete", "cloud_erasure_queued"): {
        "prep": lambda env: (env.seed_template("u_tm04"), env.force_offline()),
        "keys": ["local_removed", "cloud", "cloud_status", "bundle"]},
    ("edge.enroll.delete", "cloud_erasure_failed"): {
        "prep": _erase_queue_broken, "keys": ["local_removed", "cloud", "cloud_status", "message", "bundle"]},
    ("edge.enroll.delete", "cloud_not_configured"): {
        "app": {"cloud_on": False}, "prep": lambda env: env.seed_template("u_3c4d"),
        "keys": ["local_removed", "cloud", "cloud_status", "message", "bundle"]},
    ("edge.admin.users.list", "local_enrolments"): {
        "prep": lambda env: env.seed_template("u_3c4d", "Priya N."), "keys": ["users.0.user_id", "users.0.role",
                                                                            "users.0.bundle_role",
                                                                            "users.0.in_schedule"]},
    ("edge.mode.get", "demo_mode_clock_inactive"): {"keys": ["demo_clock.active", "demo_clock.bundle_rollback",
                                                             "demo_clock.offset_s"]},
    ("edge.mode.get", "demo_clock_evening"): {"prep": _clock("21:30"),
                                              "keys": ["demo_clock.active", "demo_clock.now_local",
                                                       "demo_clock.bundle_rollback"]},
    ("edge.mode.get", "demo_clock_rollback"): {"prep": _clock("07:00"),
                                               "keys": ["demo_clock.active", "demo_clock.bundle_rollback",
                                                        "demo_clock.cache_state"]},
    ("edge.mode.get", "not_demo_mode"): {"app": {"demo": False}, "keys": ["demo_clock"]},
    ("edge.admin.clock.post", "set_local"): {"keys": ["active", "now_local", "bundle_rollback"]},
    # the fixture bundle is issued 08:00 IST (earliest 07:55), so the replay uses 07:00 for "before earliest"
    ("edge.admin.clock.post", "set_local_before_earliest"): {"body": {"set_local": "07:00"},
                                                             "keys": ["active", "bundle_rollback", "cache_state"]},
    ("edge.admin.clock.post", "reset"): {"prep": _clock("21:30"), "keys": ["active", "offset_s", "bundle_rollback"]},
}


def test_every_valid_example_has_a_replay_spec():
    names = {(rid, ex["name"]) for rid, r in EDGE.items() for ex in r["examples"]}
    assert names == set(VALID_SPECS), {"missing": names - set(VALID_SPECS), "stale": set(VALID_SPECS) - names}


@pytest.mark.parametrize(("rid", "ex"), list(_params("valid")))
def test_valid_example_replays_through_the_handler(make_env, rid, ex):
    spec = VALID_SPECS[(rid, ex["name"])]
    env = make_env(**spec.get("app", {}))
    if spec.get("prep"):
        spec["prep"](env)
    r = send(env, rid, ex["request"], body=spec.get("body", ...))
    assert r.status_code == ex["response"]["status"], r.text
    got, want = r.json(), ex["response"]["body"]
    if rid == "edge.mode.get":
        assert got["demo_clock"] is None or DemoClock.model_validate(got["demo_clock"])
    else:
        RESPONSE_MODEL[rid].model_validate(got)  # no field lost or invented
    for k in spec["keys"]:
        if k == "warnings":
            assert bool(got["warnings"]) == bool(want["warnings"]), got["warnings"]
            continue
        if k == "warnings.0":  # exact wording; the fixture bundle version (v42) differs from the example's (v49)
            assert re.sub(r"\bv\d+", "vN", _get(got, k)) == re.sub(r"\bv\d+", "vN", _get(want, k)), got["warnings"]
            continue
        if k in ("user", "bundle", "cloud", "totp_provisioning_uri", "demo_clock", "message", "user.today"):
            assert (_get(got, k) is None) == (_get(want, k) is None), (k, _get(got, k))
            continue
        assert _get(got, k) == _get(want, k), (k, _get(got, k), _get(want, k))
    if spec.get("codes"):
        assert r.headers["cache-control"] == "no-store"
        n = ex["request"]["body"].get("count", 4)
        assert len(got["codes"]) == n and all(c["code"] for c in got["codes"])
        if spec["codes"] == "null_ids":  # R-K: code_id unknown -> null, never invented
            assert all(c["code_id"] is None for c in got["codes"]), got["codes"]
        else:
            assert all(c["code_id"] for c in got["codes"]), got["codes"]


# ================================================================== 3. lead rulings (spec audit, API v1.4)
def test_m1_erase_cloud_enum_is_the_contract_enum():
    """M1: deleted | queued | not_configured | failed (the replays above cover the handler: cloud_erasure_failed)."""
    allowed = set(EraseResponse.model_fields["cloud"].annotation.__args__)
    assert allowed == set(CONTRACT["enums"]["erase_cloud"]) == {"deleted", "queued", "not_configured", "failed"}
