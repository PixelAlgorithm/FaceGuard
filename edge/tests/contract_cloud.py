"""A contract-shaped FAKE cloud (httpx.MockTransport handler) for the edge admin-access tests.

It answers the cloud routes of docs/API.md v1.4 §4.9a / §4.3 with the shapes of docs/contracts/admin_access.
examples.json (cloud.* routes) and implements the master state rules the edge relies on (create / re-admit /
restore / revoke / rotate / enrol / erase, revocation feed with ERASE / READMIT items, per-kiosk filtered signed
bundle). Never the real cloud, never the live :8000 edge. Values are illustrative.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import json
import os
import secrets
import time
import types
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from edge.config import PROJECT_ROOT

KIOSK = "KIOSK_MAIN_01"
BUNDLE_KEY = "contract-bundle-key"
CLOUD_URL = "https://fake-cloud.test"  # EAE-07: plain http is refused unless DEMO_MODE=1
EDGE_ADMIN = "contract-edge-admin"
CLOUD_ADMIN = "contract-cloud-admin"
ADMIN = {"X-Admin-Token": EDGE_ADMIN}
EVENT_T0 = datetime(2026, 11, 14, 4, 0, tzinfo=UTC)  # before the tests' TEST_CLOCK (05:30Z): effective at once


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class ContractCloud:
    """`fail` = {(method, path_prefix): (status, json_body | None, headers)} overrides (checked first); `down` =
    transport error on every call; `stale_bundle` = GET /v1/schedule keeps serving the version it served last
    (a pull after a write cannot reach the new version); `bad_signature` = the bundle is signed with a wrong key."""

    def __init__(self, *, extra_users: bool = True, bundle_key: str = BUNDLE_KEY, kiosk: str = KIOSK) -> None:
        from edge.offline.bundle import sign_bundle

        self._sign = sign_bundle
        self.key = bundle_key
        self.kiosk = kiosk
        self.master: dict[str, Any] = json.loads(
            (PROJECT_ROOT / "config" / "schedule.example.json").read_text(encoding="utf-8"))
        self.master.pop("signature", None)
        self.version = int(self.master["bundle_version"])
        self.requests: list[dict[str, Any]] = []
        self.fail: dict[tuple[str, str], tuple[int, Any, dict[str, str]]] = {}
        self.down = False
        self.stale_bundle = False
        self.bad_signature = False
        self._served_version: int | None = None
        self.faces: dict[str, int] = {"u_3c4d": 5, "u_5e6f": 5}
        self.feed: list[dict[str, Any]] = []
        self._t = EVENT_T0
        self.staff_ids = ["s_guard01", "s_guard02"]
        if extra_users:
            users = self.master["users"]
            users["u_prj1"] = {"display": "Prajwal M.", "role": "student", "zones_add": [], "zones_remove": [],
                               "extra_windows": {}, "valid_from": None, "valid_until": None, "revoked": False,
                               "revoked_at": None, "fallback": {"totp_enrolled": False, "card_id_hash": None}}
            users["u_nf01"] = {"display": "Dr. Kavya R.", "role": "student", "zones_add": [], "zones_remove": [],
                               "extra_windows": {}, "valid_from": None, "valid_until": None, "revoked": False,
                               "revoked_at": None, "fallback": {"totp_enrolled": False, "card_id_hash": None}}
            self._revoke("u_prj1", "ERASED", feed_type="ERASE")

    def freeze_bundle(self) -> None:
        """From now on GET /v1/schedule keeps serving the CURRENT version (a later pull cannot see new writes)."""
        self.stale_bundle, self._served_version = True, self.version

    # ------------------------------------------------------------------ state helpers
    def _now(self) -> str:
        self._t += timedelta(seconds=1)
        return _iso(self._t)

    def publish(self) -> int:
        self.version += 1
        self.master["bundle_version"] = self.version
        return self.version

    def _feed(self, kind: str, target: str, reason: str, at: str) -> int:
        seq = len(self.feed) + 1
        self.feed.append({"seq": seq, "type": kind, "target_id": target, "revoked_at": at, "reason": reason})
        return seq

    def _revoke(self, uid: str, reason: str, *, feed_type: str = "USER") -> dict[str, Any]:
        at = self._now()
        self.master.setdefault("revocations", []).append({"user_id": uid, "revoked_at": at, "reason": reason})
        seq = self._feed(feed_type, uid, reason, at)
        return {"seq": seq, "revoked_at": at}

    def status(self, uid: str) -> str:
        if uid not in self.master["users"]:
            return "NOT_IN_SCHEDULE"
        reasons = [r.get("reason") for r in self.master.get("revocations") or [] if r.get("user_id") == uid]
        if any(r != "ERASED" for r in reasons):
            return "REVOKED"
        return "ERASED" if reasons else "ACTIVE"

    def _rev(self, uid: str) -> dict[str, Any] | None:
        revs = [r for r in self.master.get("revocations") or [] if r.get("user_id") == uid]
        hard = [r for r in revs if r.get("reason") != "ERASED"]
        return (hard or revs or [None])[0]

    def _user_out(self, uid: str) -> dict[str, Any]:
        u = self.master["users"][uid]
        fb = u.get("fallback") or {}
        rev = self._rev(uid) if self.status(uid) in ("REVOKED", "ERASED") else None
        return {"display": u.get("display"), "role": u.get("role"), "zones_add": list(u.get("zones_add") or []),
                "zones_remove": list(u.get("zones_remove") or []),
                "extra_windows": copy.deepcopy(u.get("extra_windows") or {}),
                "valid_from": u.get("valid_from"), "valid_until": u.get("valid_until"), "status": self.status(uid),
                "revoked_at": rev and rev.get("revoked_at"), "revoked_reason": rev and rev.get("reason"),
                "fallback": {"totp_enrolled": bool(fb.get("totp_enrolled")), "card": bool(fb.get("card_id_hash"))}}

    def filtered(self) -> dict[str, Any]:
        """filter_for_kiosk (cloud/app/services/schedule_service.py), simplified: the kiosk's zone only."""
        doc = copy.deepcopy(self.master)
        zone = doc["kiosks"][self.kiosk]["zone"]
        for r in doc["roles"].values():
            r["zones"] = [z for z in r.get("zones") or [] if z == zone]
            r["windows"] = {z: w for z, w in (r.get("windows") or {}).items() if z == zone}
        users = {}
        for uid, u in doc["users"].items():
            role = self.master["roles"].get(u.get("role")) or {}
            vp = any(p.get("user_id") == uid and zone in (p.get("zones") or []) for p in doc.get("visitor_passes") or [])
            if zone in (role.get("zones") or []) or zone in (u.get("zones_add") or []) or vp:
                u["zones_add"] = [z for z in u.get("zones_add") or [] if z == zone]
                u["zones_remove"] = [z for z in u.get("zones_remove") or [] if z == zone]
                u["extra_windows"] = {z: w for z, w in (u.get("extra_windows") or {}).items() if z == zone}
                u.pop("note", None)
                users[uid] = u
        doc["users"] = users
        doc["zones"] = {zone: doc["zones"][zone]}
        doc["kiosks"] = {self.kiosk: doc["kiosks"][self.kiosk]}
        doc["scope"] = {"kiosk_ids": [self.kiosk]}
        doc["revocations"] = [r for r in doc.get("revocations") or [] if r.get("user_id") in users]
        doc["visitor_passes"] = [p for p in doc.get("visitor_passes") or [] if p.get("user_id") in users]
        return doc

    def signed(self) -> dict[str, Any]:
        doc = self.filtered()
        if self.stale_bundle and self._served_version is not None:
            doc["bundle_version"] = self._served_version
        key = b"wrong-key" if self.bad_signature else self.key.encode()
        return self._sign(doc, key)

    def calls(self, method: str, prefix: str) -> list[dict[str, Any]]:
        return [r for r in self.requests if r["method"] == method and r["path"].startswith(prefix)]

    @staticmethod
    def err(status: int, code: str, message: str, reason: str | None = None) -> httpx.Response:
        body: dict[str, Any] = {"code": code, "message": message}
        if reason:
            body["reason"] = reason
        return httpx.Response(status, json={"error": body})

    # ------------------------------------------------------------------ routes
    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            raise httpx.ConnectError("fake cloud down", request=request)
        m, path = request.method, request.url.path
        body = json.loads(request.content) if request.content else None
        query = dict(request.url.params)
        # probe 10b: every write carries a per-call request_id (signed); recorded apart so body asserts stay exact
        rid = (body.pop("request_id", None) if isinstance(body, dict) else None) or query.pop("request_id", None)
        self.requests.append({"method": m, "path": path, "headers": dict(request.headers), "json": body,
                              "query": query, "request_id": rid})
        for (fm, fp), (status, fbody, fh) in self.fail.items():
            if fm == m and path.startswith(fp):
                return httpx.Response(status, json=fbody, headers=fh) if fbody is not None else \
                    httpx.Response(status, headers=fh)
        users = self.master["users"]
        if path == "/v1/health":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/v1/revocations" and m == "GET":
            since = int(request.url.params.get("since") or 0)
            return httpx.Response(200, json={"as_of": _iso(self._t), "revocation_seq": len(self.feed),
                                             "items": [i for i in self.feed if i["seq"] > since]})
        if path == f"/v1/schedule/{self.kiosk}" and m == "GET":
            served = self._served_version if self.stale_bundle and self._served_version is not None else self.version
            if request.headers.get("If-None-Match") == f'"{served}"':
                return httpx.Response(304)
            self._served_version = served
            return httpx.Response(200, json=self.signed())
        if path == "/v1/match":
            return httpx.Response(200, json={"user_id": None, "similarity": None})
        if path == "/v1/sync" and m == "POST":
            return httpx.Response(200, json={"accepted": [i.get("attempt_id") for i in body.get("items") or []],
                                             "duplicates": [], "rejected": [], "flags": []})
        if path == "/v1/admin/users" and m == "GET":
            return httpx.Response(200, json={
                "as_of": _iso(self._t), "bundle_version": self.version, "published_at": self.master.get("issued_at"),
                "timezone": "Asia/Kolkata", "roles": copy.deepcopy(self.master["roles"]),
                "zones": copy.deepcopy(self.master["zones"]), "kiosks": copy.deepcopy(self.master["kiosks"]),
                "staff_ids": list(self.staff_ids),
                "users": [{"user_id": uid, **self._user_out(uid), "in_schedule": True,
                           "enrolled": self.faces.get(uid, 0) > 0, "faces": self.faces.get(uid, 0),
                           "consent_version": "2026-11-14.v1"} for uid in sorted(users)]})
        if path.startswith("/v1/admin/users/") and path.endswith("/access") and m == "PUT":
            return self._put_access(path.split("/")[4], body or {})
        if path == "/v1/admin/revocations" and m == "POST":
            uid = body["target_id"]
            if body.get("reason") == "ERASED":
                return self.err(422, "VALIDATION_ERROR", "ERASED is reserved", None)
            if uid not in users:
                return self.err(404, "NOT_FOUND", f"unknown user_id {uid}", "UNKNOWN_USER")
            if self.status(uid) == "REVOKED":
                return self.err(409, "INVALID_STATE", f"user {uid} is already revoked", "ALREADY_REVOKED")
            out = self._revoke(uid, body.get("reason") or "ADMIN")
            return httpx.Response(201, json={"seq": out["seq"], "type": "USER", "target_id": uid,
                                             "revoked_at": out["revoked_at"], "reason": body.get("reason") or "ADMIN",
                                             "bundle_version": self.publish()})
        if path == "/v1/admin/codes/rotate" and m == "POST":
            n = int(body.get("count") or 4)
            codes = [{"code_id": f"OVR-R{self.version + 1}-{i + 1:02d}", "code": f"{secrets.randbelow(10**8):08d}"}
                     for i in range(n)]
            oc = self.master.setdefault("override_codes", {"codes": []})
            dropped = []
            if body.get("replace_existing", True):
                dropped = [c["code_id"] for c in oc.get("codes") or [] if c.get("staff_id") == body["staff_id"]]
                oc["codes"] = [c for c in oc.get("codes") or [] if c.get("staff_id") != body["staff_id"]]
            return httpx.Response(201, headers={"Cache-Control": "no-store", "Pragma": "no-cache"}, json={
                "staff_id": body["staff_id"], "bundle_version": self.publish(), "codes": codes,
                "dropped_code_ids": dropped, "code_length": 8, "valid_until": "2026-11-16T00:40:00Z", "one_time": True,
                "warning": "Shown once: store these codes safely (each works once, for this staff_id only)."})
        if path == "/v1/otp/send":
            return httpx.Response(201, json={"otp_id": "otp_1", "destination_masked": "p***@x.in", "ttl_s": 300})
        if path == "/v1/enroll" and m == "POST":
            uid = body["user_id"]
            self.faces[uid] = len(body["images_b64"])
            if uid in users:
                fb = users[uid].setdefault("fallback", {})
                fb["totp_enrolled"] = bool(body.get("totp_enrolled"))
                if body.get("card_id_hash"):
                    fb["card_id_hash"] = body["card_id_hash"]
            return httpx.Response(201, json={"user_id": uid, "faces_indexed": len(body["images_b64"]),
                                             "bundle_version": self.publish(),
                                             "totp_provisioning_uri": "otpauth://totp/cloud-secret-must-not-leak"})
        if path.startswith("/v1/enroll/") and m == "DELETE":
            uid = path.split("/")[3]
            self.faces.pop(uid, None)
            if uid in users and self.status(uid) != "ERASED":
                self._revoke(uid, "ERASED", feed_type="ERASE")
            return httpx.Response(200, json={"erased": True, "bundle_version": self.publish()})
        return self.err(404, "NOT_FOUND", "Not Found")

    def _put_access(self, uid: str, body: dict[str, Any]) -> httpx.Response:
        users, master = self.master["users"], self.master
        role = body.get("role")
        if role not in master["roles"]:
            return self.err(422, "VALIDATION_ERROR", f"unknown role {role!r}", "UNKNOWN_ROLE")
        named = set(body.get("zones_add") or []) | set(body.get("extra_windows") or {})
        bad = sorted(named - set(master["zones"]))
        if bad:
            return self.err(422, "VALIDATION_ERROR", f"unknown zones {bad}", "UNKNOWN_ZONE")
        consent, restore = body.get("consent") is True, body.get("restore") is True
        created = uid not in users
        readmitted = restored = False
        warnings: list[str] = []
        if created:
            if not body.get("display"):
                return self.err(422, "VALIDATION_ERROR", "display is required to add a new user", "DISPLAY_REQUIRED")
            if not consent:
                return self.err(422, "VALIDATION_ERROR", "consent: true is required to add a new user",
                                "CONSENT_REQUIRED")
            users[uid] = {"display": body["display"], "role": role, "zones_add": [], "zones_remove": [],
                          "extra_windows": {}, "valid_from": None, "valid_until": None, "revoked": False,
                          "revoked_at": None, "fallback": {"totp_enrolled": False, "card_id_hash": None}}
        status = self.status(uid)
        if status == "REVOKED":
            if consent and restore:
                at = self._now()
                master["revocations"] = [r for r in master["revocations"] if r.get("user_id") != uid]
                self._feed("READMIT", uid, "RESTORE", at)
                restored = True
            elif consent:
                return self.err(409, "INVALID_STATE", f"user {uid} is revoked: use Restore (restore: true) first",
                                "USER_REVOKED")
            else:
                warnings.append("user is revoked: access changes do not lift a revocation (use Restore)")
        elif status == "ERASED":
            if not consent:
                return self.err(409, "INVALID_STATE", f"user {uid} was erased (DPDP): re-admit with consent: true",
                                "ERASED_IN_BUNDLE")
            at = self._now()
            master["revocations"] = [r for r in master["revocations"]
                                     if not (r.get("user_id") == uid and r.get("reason") == "ERASED")]
            self._feed("READMIT", uid, "READMIT", at)
            readmitted = True
        u = users[uid]
        before = copy.deepcopy(u)
        previous_role = None if created else before.get("role")
        for k in ("display", "role", "zones_add", "extra_windows", "valid_from", "valid_until"):
            if k in body:
                u[k] = copy.deepcopy(body[k])
        unchanged = not (created or readmitted or restored) and u == before
        version = self.version if unchanged else self.publish()
        return httpx.Response(200, json={
            "user_id": uid, "bundle_version": version, "created": created, "unchanged": unchanged,
            "readmitted": readmitted, "restored": restored, "previous_role": previous_role, "role": u["role"],
            "user": self._user_out(uid), "changed_at": None if unchanged else _iso(self._t), "warnings": warnings})


# ================================================================== scratch edge app wired to the fake
STAFF_PW = "orbit-tangerine-971-pytest"  # dummy, test-only


def staff_headers(ctx: Any, username: str, roles: list[str]) -> dict[str, str]:
    """A signed-in staff session (Authorization: Bearer) on the scratch edge's AuthService: staff_id s_<username>."""
    from edge.auth.staff_ops import cli_principal

    auth = ctx.auth
    if not auth.staff_exists(f"s_{username}"):
        auth.create_staff(cli_principal("pytest"), username, username.title(), roles, STAFF_PW,
                          must_change_password=False)
    token = auth.login_sync(username, STAFF_PW)[0]
    return {"Authorization": f"Bearer {token}"}


class Env:
    def __init__(self, c: TestClient, ctx: Any, cloud: ContractCloud) -> None:
        self.c, self.ctx, self.cloud = c, ctx, cloud

    def staff(self, username: str = "guard01", roles: tuple[str, ...] = ("security_officer",)) -> dict[str, str]:
        return staff_headers(self.ctx, username, list(roles))

    def force_offline(self) -> None:
        assert self.c.post("/v1/admin/mode", json={"force": "OFFLINE"}, headers=ADMIN).status_code == 200

    def put(self, uid: str, body: dict[str, Any]) -> dict[str, Any]:
        r = self.c.put(f"/v1/admin/access/users/{uid}", json=body, headers=ADMIN)
        assert r.status_code == 200, r.text
        return r.json()

    def seed_template(self, uid: str, display: str = "Seeded", role: str = "student") -> None:
        rng = np.random.default_rng(abs(hash(uid)) % 2**32)
        e = rng.normal(size=(5, 512)).astype(np.float32)
        e /= np.linalg.norm(e, axis=1, keepdims=True)
        self.ctx.templates.upsert(user_id=uid, display_name=display, role=role, embeddings=e,
                                  consent_version="2026-11-14.v1", card_id_hash=None, totp_secret=None)


def _runtime(tmp_path, cloud: ContractCloud | None, demo: bool):
    from edge.policy.runtime import PolicyRuntime

    fake = cloud or ContractCloud()
    path = tmp_path / "bundle.signed.json"
    path.write_text(json.dumps(fake.signed()), encoding="utf-8")
    env = {"KIOSK_ID": KIOSK, "EDGE_DATA_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
           "EDGE_DATA_DIR": str(tmp_path), "SCHEDULE_BUNDLE_HMAC_KEY": BUNDLE_KEY, "BUNDLE_PATH": str(path),
           "CLOUD_API_URL": CLOUD_URL if cloud is not None else "", "DEMO_MODE": "1" if demo else "0",
           "CARD_ID_PEPPER": "contract-pepper", "KIOSK_HMAC_KEY": "contract-kiosk-key",
           "CLOUD_API_KEY": "contract-api-key"}
    rt = PolicyRuntime.from_env(PROJECT_ROOT, env=env, transport=httpx.MockTransport(fake.handler))
    rt.start = lambda: None  # no background loop: every cloud call is explicit
    rt.stop = lambda: None
    if cloud is not None:
        for _ in range(int(rt.cfg.connectivity.successes_to_online)):
            assert rt.heartbeat()
        rt.sync_now()
        assert rt.mode() == "ONLINE", rt.mode_status()
    return rt


@pytest.fixture
def make_env(request, tmp_path, settings, thresholds):
    stack = ExitStack()
    n = [0]

    def build(*, cloud_on: bool = True, demo: bool = True, models: bool = False) -> Env:
        from edge.app import create_app
        from edge.attempts import EdgeContext
        from edge.cloud_client import CloudClient
        from edge.depth_bridge import DepthBridge
        from edge.events import EventBus
        from edge.metrics import MetricsStore
        from edge.ml.templates import TemplateStore
        from edge.perception import EngineHealth
        from edge.session import AttemptStore

        n[0] += 1
        d = tmp_path / f"env{n[0]}"
        d.mkdir()
        cloud = ContractCloud()
        s = dataclasses.replace(settings, kiosk_id=KIOSK, cloud_api_url=CLOUD_URL if cloud_on else "",
                                cloud_api_key="contract-api-key", kiosk_hmac_key="contract-kiosk-key",
                                admin_token=EDGE_ADMIN, cloud_admin_token=CLOUD_ADMIN, data_dir=d, lan_port=0,
                                demo_mode=demo, card_id_pepper="contract-pepper")
        rt = _runtime(d, cloud if cloud_on else None, demo)
        if models:
            engine = request.getfixturevalue("engine")  # session-scoped; skips without the weights
        else:
            engine = types.SimpleNamespace(health=EngineHealth(), ready=False, detector=None, embedder=None, pad=None)
        model_id = engine.embedder.model_id if getattr(engine, "embedder", None) else "fake_arcface"
        store = TemplateStore(d / "templates.fernet", s.edge_data_key, model_id)
        store.load()
        pool = ThreadPoolExecutor(max_workers=4)
        ctx = EdgeContext(settings=s, thresholds=thresholds, engine=engine, runtime=rt, runtime_kind="policy",
                          sessions=AttemptStore(), events=EventBus(), metrics=MetricsStore(),
                          cloud=CloudClient(s, thresholds, transport=httpx.MockTransport(cloud.handler)),
                          depth=DepthBridge(thresholds), templates=store, pool=pool,
                          started_monotonic=time.monotonic())
        c = stack.enter_context(TestClient(create_app(lambda: ctx)))
        return Env(c, ctx, cloud)

    yield build
    stack.close()


def _face_frames() -> list[bytes]:
    from edge import synth

    return [synth.jpeg(synth.base_frame(shift_px=s)) for s in (-8, -4, 0, 4, 8)]


def _blank_frames() -> list[bytes]:
    from edge import synth

    return [synth.jpeg(np.full((480, 640, 3), 90, dtype=np.uint8)) for _ in range(5)]
