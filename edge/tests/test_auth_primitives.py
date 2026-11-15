"""Unit tests for edge/auth primitives: RBAC catalog, scrypt password hashing + policy, bearer token formats."""

from __future__ import annotations

import pytest

from edge.auth import passwords, rbac, tokens


# ------------------------------------------------------------------ rbac
def test_admin_has_every_edge_permission_and_unknown_roles_grant_nothing():
    assert rbac.permissions_for(["admin"]) == frozenset(str(p) for p in rbac.EdgePermission)
    assert rbac.permissions_for(["root", "superuser"]) == frozenset()
    assert rbac.permissions_for([]) == frozenset()


def test_permissions_are_plain_strings_and_union_of_roles():
    perms = rbac.permissions_for(["enroller", "auditor"])
    assert all(type(p) is str for p in perms)
    assert {"enrol:write", "audit:read", "events:read"} <= perms
    assert "staff:manage" not in perms


@pytest.mark.parametrize("role", ["security_officer", "enroller", "auditor", "evaluator"])
def test_only_admin_can_manage_staff_or_rotate_codes_for_others(role):
    perms = rbac.permissions_for([role])
    assert "staff:manage" not in perms
    assert "codes:rotate_any" not in perms


def test_validate_roles_normalises_and_rejects_bad_sets():
    assert rbac.validate_roles(["auditor", "enroller", "auditor"]) == ("auditor", "enroller")
    for bad in ([], ["root"], ["admin", "auditor", "enroller", "evaluator"]):
        with pytest.raises(ValueError):
            rbac.validate_roles(bad)


def test_has_permissions_never_grants_an_empty_requirement():
    assert rbac.has_permissions(["audit:read"], ["audit:read"])
    assert not rbac.has_permissions(["audit:read"], ["audit:read", "staff:manage"])
    assert not rbac.has_permissions(["audit:read"], [])


def test_cloud_edge_proxy_cannot_read_audit_or_write_schedules():
    perms = rbac.permissions_for(["edge_proxy"], rbac.CLOUD_ROLES)
    assert "schedule:write" not in perms and "audit:read" not in perms
    assert "codes:rotate" in perms


# ------------------------------------------------------------------ rbac v2 (design v2 section B)
def test_demo_control_is_split_into_admin_only_clock_and_evaluator_challenge():
    assert "demo:control" not in {str(p) for p in rbac.EdgePermission}
    assert "demo:clock" in rbac.permissions_for(["admin"])
    assert "demo:clock" not in rbac.permissions_for(["evaluator", "security_officer", "enroller"])
    assert "challenge:control" in rbac.permissions_for(["evaluator"])
    assert rbac.DEMO_ONLY_PERMISSIONS == {"demo:clock", "challenge:control"}


def test_v2_role_catalog_for_evaluator_and_enroller():
    assert {"mode:switch", "store:read"} <= rbac.permissions_for(["evaluator"])
    assert rbac.permissions_for(["enroller"]) == {"enrol:read", "enrol:write", "enrol:erase", "access:read",
                                                  "bundle:refresh"}
    assert "access:edit" not in rbac.permissions_for(["enroller"])


def test_api_keys_never_hold_forbidden_permissions_or_the_admin_role():
    assert rbac.KEY_FORBIDDEN_PERMISSIONS == {"staff:manage", "codes:rotate", "codes:rotate_any", "access:edit",
                                              "access:revoke", "enrol:erase", "demo:clock"}
    perms = rbac.key_permissions(["security_officer", "enroller", "evaluator"])
    assert not perms & rbac.KEY_FORBIDDEN_PERMISSIONS and "events:read" in perms
    with pytest.raises(ValueError):
        rbac.validate_key_roles(["admin"])
    assert rbac.validate_key_roles(["evaluator", "enroller"]) == ("enroller", "evaluator")


def test_legacy_token_is_admin_minus_staff_management_and_any_id_codes():
    assert rbac.LEGACY_PERMISSIONS == rbac.permissions_for(["admin"]) - {"staff:manage", "codes:rotate_any"}


def test_cloud_edge_proxy_lost_contact_edit():
    assert "contact:edit" not in rbac.permissions_for(["edge_proxy"], rbac.CLOUD_ROLES)


def test_route_maps_are_disjoint_use_known_permissions_and_cover_every_permission():
    mapped = set(rbac.ROUTE_PERMISSIONS)
    assert not mapped & rbac.PUBLIC_ROUTES and not mapped & rbac.DEPTH_DEVICE_ROUTES
    assert not rbac.PUBLIC_ROUTES & rbac.DEPTH_DEVICE_ROUTES
    known = {str(p) for p in rbac.EdgePermission}
    used = {p for perms in rbac.ROUTE_PERMISSIONS.values() for p in perms}
    assert used <= known
    assert known - used == {"codes:rotate_any"}  # checked inside the codes/rotate handler
    assert all(type(p) is str for perms in rbac.ROUTE_PERMISSIONS.values() for p in perms)
    assert isinstance(rbac.RBAC_VERSION, int) and rbac.RBAC_VERSION >= 2


def test_public_routes_are_exactly_the_v2_list():
    attempt = "/v1/attempt/{attempt_id}"
    assert rbac.PUBLIC_ROUTES == {
        ("GET", "/v1/health"), ("GET", "/v1/mode"), ("GET", "/v1/auth/status"), ("POST", "/v1/auth/login"),
        ("POST", "/v1/session/start"), ("GET", attempt),
        *(("POST", f"{attempt}/{leaf}") for leaf in ("frames", "probe", "rendered", "challenge", "fallback",
                                                      "otp/send")),
    }


# ------------------------------------------------------------------ passwords
@pytest.fixture
def fast_scrypt(monkeypatch):
    monkeypatch.setattr(passwords, "SCRYPT_LOG2_N", 10)
    monkeypatch.setattr(passwords, "SCRYPT_P", 1)


def test_hash_verify_roundtrip_and_wrong_password(fast_scrypt):
    h = passwords.hash_password("tangerine-orbit-42")
    assert h.startswith("scrypt$10$8$1$")
    assert passwords.verify_password("tangerine-orbit-42", h)
    assert not passwords.verify_password("tangerine-orbit-43", h)


def test_salts_are_random(fast_scrypt):
    assert passwords.hash_password("same-password-xyz") != passwords.hash_password("same-password-xyz")


@pytest.mark.parametrize("encoded", [None, "", "md5$abc", "scrypt$99$8$1$AAAA$BBBB", "scrypt$10$8$1$!!$??",
                                     "scrypt$x$8$1$AAAA$BBBB", "scrypt$24$8$1$AAAAAAAAAAAAAAAAAAAAAA$" + "A" * 43])
def test_malformed_or_hostile_hashes_fail_closed_without_raising(fast_scrypt, encoded):
    assert passwords.verify_password("whatever-pass", encoded) is False


def test_nfkc_normalisation_matches_fullwidth_input(fast_scrypt):
    h = passwords.hash_password("password-xyz-12")
    assert passwords.verify_password("ｐａｓｓｗｏｒｄ-ｘｙｚ-１２", h)


def test_needs_rehash_flags_weaker_parameters(fast_scrypt, monkeypatch):
    weak = passwords.hash_password("tangerine-orbit-42")
    monkeypatch.setattr(passwords, "SCRYPT_LOG2_N", 11)
    assert passwords.needs_rehash(weak)
    assert passwords.needs_rehash("garbage")


def test_empty_or_oversized_passwords_are_rejected(fast_scrypt):
    h = passwords.hash_password("tangerine-orbit-42")
    assert not passwords.verify_password("", h)
    assert not passwords.verify_password("x" * 10_000, h)
    with pytest.raises(ValueError):
        passwords.hash_password("")


@pytest.mark.parametrize(("pw", "user", "expected"), [
    ("short", "", "at least 12"),
    ("aaaaaaaaaaaaaaaa", "", "different characters"),
    ("guard01-secret-pass", "guard01", "username"),
    ("Password1234", "", "too common"),
])
def test_password_policy_violations(pw, user, expected):
    problems = passwords.check_policy(pw, user)
    assert any(expected in p for p in problems), problems


def test_password_policy_accepts_a_reasonable_passphrase():
    assert passwords.check_policy("tangerine-orbit-42", "guard01") == []


# ------------------------------------------------------------------ tokens
def test_session_tokens_are_well_formed_and_unique():
    a, b = tokens.new_session_token(), tokens.new_session_token()
    assert a != b and tokens.is_session_token(a) and len(a) == 47
    assert not tokens.is_session_token(a + "x") and not tokens.is_session_token(None)


def test_api_key_roundtrip_and_digest_compare():
    key_id, full, stored = tokens.new_api_key()
    parsed = tokens.parse_api_key(full)
    assert parsed is not None and parsed[0] == key_id
    assert tokens.digests_equal(tokens.digest(parsed[1]), stored)
    assert not tokens.digests_equal(tokens.digest(parsed[1] + "x"), stored)


@pytest.mark.parametrize("raw", [None, "", "fgk_bad", "fgk_ABCDEFGH.x", "fgs_" + "a" * 43])
def test_parse_api_key_rejects_other_shapes(raw):
    assert tokens.parse_api_key(raw) is None


@pytest.mark.parametrize(("header", "expected"), [
    ("Bearer abc", "abc"), ("bearer  abc ", "abc"), ("Basic abc", None), ("Bearer", None),
    ("Bearer a b", None), (None, None), ("Bearer " + "a" * 300, None),
])
def test_parse_bearer(header, expected):
    assert tokens.parse_bearer(header) == expected
