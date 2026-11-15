"""Cloud enrolment APPENDS faces (edge parity: edge/enroll.py + edge/ml/templates.py, glasses on / off) and a
failed (re-)enrolment never removes the user's existing Rekognition faces.

Regression: the deployed build ran DeleteUser + DeleteFaces on the old faces BEFORE validating the new frames,
so a re-enrolment that then failed (no usable face, throttling) left the user with no faces -> online
NOT_ENROLLED -> DENY; faces indexed before a mid-way failure were never deleted.
"""

from __future__ import annotations

import base64
import uuid

import pytest

from cloud.app.config import ConfigError, settings_from_env
from cloud.app.services.enroll_service import plan_eviction
from cloud.app.services.faces import FaceError
from cloud.tools.fakeimg import make_fake_jpeg

USER = "u_3c4d"


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def frames(spec: str, n: int, tag: str) -> list[bytes]:
    return [make_fake_jpeg(spec, salt=f"{tag}{i}") for i in range(n)]


def meta(user: str = USER) -> dict:
    return {"user_id": user, "display_name": "Priya N.", "email": "priya@example.org", "groups": ["student"],
            "consent": True, "consent_version": "2026-11-14.v1", "provision_totp": False}


def enroll(signed, imgs: list[bytes], user: str = USER):
    return signed.post("/v1/enroll", {**meta(user), "images_b64": [b64(i) for i in imgs]})


def matches(signed, user: str = USER) -> bool:
    m = signed.post("/v1/match", {"attempt_id": f"att_{uuid.uuid4().hex[:12]}", "kiosk_id": "KIOSK_LIB_01",
                                  "image_b64": b64(make_fake_jpeg(user, salt="probe"))}).json()
    return m["matched"] is True and m["user_id"] == user


def user_faces(services, user: str = USER) -> list[str]:
    return sorted(services.faces.list_user_faces(user))


def fail_on_call(services, method: str, n: int, kind: str = "THROTTLED") -> None:
    """Make the n-th call of services.faces.<method> raise FaceError(kind)."""
    real = getattr(services.faces, method)
    seen = {"n": 0}

    def flaky(*a, **k):
        seen["n"] += 1
        if seen["n"] == n:
            raise FaceError(kind, "ThrottlingException")
        return real(*a, **k)

    setattr(services.faces, method, flaky)


@pytest.fixture
def first(signed, services) -> dict:
    services.enroll.bucket = None  # no IndexFaces pacing in unit tests
    r = enroll(signed, frames(USER, 3, "a"))
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ failed re-enrolment changes nothing
def test_failed_reenroll_noface_is_422_and_user_still_matches(signed, services, first):
    n0, calls0 = services.faces.face_count(), len(services.faces.calls)
    r = enroll(signed, [make_fake_jpeg("NOFACE", salt="n1")])
    assert r.status_code == 422 and r.json()["error"]["code"] == "VALIDATION_ERROR"
    assert not {"DeleteUser", "DeleteFaces", "DisassociateFaces"} & set(services.faces.calls[calls0:])
    assert services.faces.face_count() == n0 and user_faces(services) == sorted(first["face_ids"])
    row = services.kv.get("users", USER)
    assert row["face_ids"] == first["face_ids"] and row["template_version"] == 1
    assert matches(signed)


def test_reenroll_throttled_on_index_call_2_keeps_face_count(signed, services, first):
    n0 = services.faces.face_count()
    fail_on_call(services, "index_face", 2)
    r = enroll(signed, frames(USER, 3, "b"))
    assert r.status_code == 503 and r.json()["error"]["code"] == "UPSTREAM_THROTTLED"
    assert services.faces.face_count() == n0  # the face indexed by call 1 was deleted again
    assert user_faces(services) == sorted(first["face_ids"])
    assert services.kv.get("users", USER)["face_ids"] == first["face_ids"]
    assert matches(signed)


def test_throttled_associate_removes_the_new_faces(signed, services, first):
    n0 = services.faces.face_count()
    fail_on_call(services, "associate_faces", 1)
    r = enroll(signed, frames(USER, 2, "b"))
    assert r.status_code == 503 and services.faces.face_count() == n0
    assert user_faces(services) == sorted(first["face_ids"]) and matches(signed)


def test_throttled_first_enrolment_leaves_nothing_behind(signed, services):
    services.enroll.bucket = None
    fail_on_call(services, "index_face", 2)
    r = enroll(signed, frames(USER, 3, "a"))
    assert r.status_code == 503 and r.json()["error"]["code"] == "UPSTREAM_THROTTLED"
    assert services.faces.face_count() == 0 and services.kv.get("users", USER) is None
    assert not matches(signed)


def test_row_write_failure_undoes_only_the_new_faces(services, first):
    before, n0 = user_faces(services), services.faces.face_count()
    real_put = services.kv.put

    def failing_put(ns, key, item, ttl=None):
        if ns == "users":
            raise RuntimeError("store down")
        return real_put(ns, key, item, ttl)

    services.kv.put = failing_put
    with pytest.raises(RuntimeError):
        services.enroll.enroll(meta(), frames(USER, 2, "b"))
    assert services.faces.face_count() == n0 and user_faces(services) == before


# ------------------------------------------------------------------ append semantics
def test_reenroll_appends_and_face_count_grows(signed, services, first):
    r = enroll(signed, frames(USER, 2, "glasses"))
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["faces_indexed"] == 2 and out["frames_rejected"] == 0 and out["template_version"] == 2
    assert out["face_ids"][:3] == first["face_ids"] and len(out["face_ids"]) == 5  # old faces kept, oldest first
    assert len(user_faces(services)) == 5 and services.faces.face_count() == 5
    assert "DeleteUser" not in services.faces.calls and "DeleteFaces" not in services.faces.calls
    assert services.kv.get("users", USER)["face_ids"] == out["face_ids"]
    assert matches(signed)


def test_different_face_cannot_be_appended(signed, services, first):
    """AssociateFaces only adds a face that matches the existing user (UserMatchThreshold from thresholds.yaml)."""
    assert services.enroll.match_threshold == services.thresholds.user_match_threshold == 80.0
    n0 = services.faces.face_count()
    r = enroll(signed, frames("u_1a2b", 2, "x"))
    assert r.status_code == 409 and r.json()["error"]["code"] == "INVALID_STATE"
    assert services.faces.face_count() == n0 and user_faces(services) == sorted(first["face_ids"])
    assert matches(signed)


def test_partially_refused_frames_keep_only_the_matching_faces(signed, services, first):
    n0 = services.faces.face_count()
    r = enroll(signed, [make_fake_jpeg(USER, salt="g1"), make_fake_jpeg("u_1a2b", salt="x1")])
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["faces_indexed"] == 1 and out["frames_rejected"] == 1 and len(out["face_ids"]) == 4
    assert services.faces.face_count() == n0 + 1  # the refused face is deleted, not left in the collection


def test_cap_24_keeps_the_first_5_and_the_newest(signed, services):
    services.enroll.bucket = None
    first = enroll(signed, frames(USER, 5, "a")).json()["face_ids"]
    second = [f for f in enroll(signed, frames(USER, 10, "b")).json()["face_ids"] if f not in first]
    r = enroll(signed, frames(USER, 10, "c"))
    assert r.status_code == 201, r.text
    ids = r.json()["face_ids"]
    third = [f for f in ids if f not in first + second]
    assert len(ids) == 24 and ids[:5] == first and len(third) == 10  # 25 -> 24
    assert second[0] not in ids and ids[5:14] == second[1:] and ids[14:] == third  # oldest unpinned evicted
    assert services.faces.face_count() == 24  # evicted face deleted from the collection, not just unlinked
    assert user_faces(services) == sorted(ids) and services.kv.get("users", USER)["face_ids"] == ids


def test_eviction_failure_never_fails_or_shrinks_the_enrolment(signed, services, first):
    services.enroll.max_faces, services.enroll.pinned_faces = 4, 3  # 3 + 2 new faces -> one eviction due

    def boom(*_a, **_k):
        raise FaceError("CONFLICT", "user UPDATING")

    services.faces.disassociate_faces = boom
    r = enroll(signed, frames(USER, 2, "b"))
    assert r.status_code == 201 and len(r.json()["face_ids"]) == 5 and len(user_faces(services)) == 5


def test_erase_after_appends_deletes_every_face_even_ones_the_row_misses(signed, services, first):
    assert enroll(signed, frames(USER, 2, "b")).status_code == 201
    drift = services.faces.index_face(make_fake_jpeg(USER, salt="drift"), USER, "AUTO")  # e.g. concurrent enrol
    services.faces.associate_faces(USER, [drift], "tok")
    r = signed.delete(f"/v1/enroll/{USER}")
    assert r.status_code == 200 and r.json()["faces_deleted"] == 6
    assert services.faces.face_count() == 0 and USER not in services.faces.user_ids()


# ------------------------------------------------------------------ cap rule + config
def test_plan_eviction_same_rule_as_edge_templates():
    ids = [f"f{i}" for i in range(30)]
    assert plan_eviction(ids[:24], 24, 5) == (ids[:24], [])
    keep, evict = plan_eviction(ids, 24, 5)
    assert keep == ids[:5] + ids[11:] and evict == ids[5:11]
    assert plan_eviction(ids[:7], 6, 5) == (ids[:5] + ids[6:7], ids[5:6])


def test_config_validates_enrolment_caps():
    env = {"KIOSK_HMAC_KEY": "k", "SCHEDULE_BUNDLE_HMAC_KEY": "b", "CLOUD_API_KEY": "a", "ADMIN_TOKEN": "t"}
    s = settings_from_env(env, load_env_file=False)
    assert (s.enroll_min_faces, s.enroll_max_faces_per_user, s.enroll_pinned_faces) == (1, 24, 5)
    for bad in ({"ENROLL_PINNED_FACES": "24"}, {"ENROLL_MAX_FACES_PER_USER": "101"}, {"ENROLL_MIN_FACES": "0"}):
        with pytest.raises(ConfigError):
            settings_from_env({**env, **bad}, load_env_file=False)
