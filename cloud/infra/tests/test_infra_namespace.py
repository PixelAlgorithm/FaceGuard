"""CIT-01: deploy state and data-plane names are namespaced by prefix/region; defaults stay backward compatible."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

STAGING = "hid-kiosk-staging"


def test_default_names_unchanged(h):
    r = h.bash('echo "$COLLECTION_ID $DDB_USERS $DDB_DECISIONS $DDB_STATE $HID_TAG_VALUE $ROLE_EC2 $STATE_FILE"')
    assert r.returncode == 0, r.stderr
    coll, users, dec, st, tag, role, state_file = r.stdout.split()
    assert (coll, users, dec, st, tag, role) == (
        "hid-kiosk-users", "hid_users", "hid_decisions", "hid_state", "hid-kiosk", "hid-kiosk-ec2-role")
    assert state_file.endswith("/deploy.env")


def test_staging_prefix_derives_every_name(h):
    r = h.bash('echo "$COLLECTION_ID $DDB_USERS $DDB_DECISIONS $DDB_STATE $HID_TAG_VALUE $STATE_FILE"',
               HID_PREFIX=STAGING)
    assert r.returncode == 0, r.stderr
    coll, users, dec, st, tag, state_file = r.stdout.split()
    assert coll == "hid-kiosk-staging-users"
    assert (users, dec, st) == ("hid_kiosk_staging_users", "hid_kiosk_staging_decisions", "hid_kiosk_staging_state")
    assert tag == STAGING
    assert state_file.endswith(f"/{STAGING}.env")


def test_non_default_region_namespaces_global_iam_names_and_state(h):
    r = h.bash('echo "$ROLE_EC2 $DASHBOARD $STATE_FILE"', HID_REGION="ap-south-1")
    role, dash, state_file = r.stdout.split()
    # CI-08: "<prefix>--<region>" so prefix P in region R never collides with prefix "P-R" in us-east-1
    assert role == "hid-kiosk--ap-south-1-ec2-role"
    assert dash == "hid-kiosk--ap-south-1"
    assert state_file.endswith("/hid-kiosk--ap-south-1.env")


def test_invalid_prefix_refused(h):
    r = h.bash("echo ok", HID_PREFIX="Bad_Prefix;rm")
    assert r.returncode != 0
    assert "HID_PREFIX" in r.stderr


def test_staging_teardown_plan_never_targets_production_names(h):
    r = h.run("teardown.sh", HID_PREFIX=STAGING)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "--table-name hid_users" not in out
    assert "--collection-id hid-kiosk-users" not in out
    assert "Values=hid-kiosk>" not in out and "Values=hid-kiosk " not in out
    assert "hid_kiosk_staging_users" in out and "hid-kiosk-staging-users" in out


def test_staging_replace_does_not_see_production_instance(h):
    h.write_state({"INSTANCE_ID": "i-prod", "PUBLIC_DNS": "prod.example"})  # production deploy.env
    r = h.run("deploy_ec2.sh", "--skip-build", "--replace", "--demo", HID_PREFIX=STAGING)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "i-prod" not in r.stdout


def test_state_load_ignores_unknown_keys(h):
    h.write_state({"APPLY": "1", "INSTANCE_ID": "i-1", "PATH": "/evil"})
    r = h.bash('load_state; echo "$APPLY $INSTANCE_ID"; command -v bash >/dev/null && echo pathok')
    assert r.stdout.split() == ["0", "i-1", "pathok"]


def test_collection_override_recorded_and_used_by_teardown(h):
    h.not_found("describe-collection")
    h.not_found("describe-table")
    h.rule("head-bucket", stdout="{}")
    r = h.run("data_plane.sh", "--apply", "--skip-s3", "--skip-cloudwatch",
              REKOGNITION_COLLECTION_ID_OVERRIDE="custom-faces")
    assert r.returncode == 0, r.stdout + r.stderr
    st = h.state()
    assert st["COLLECTION_ID"] == "custom-faces"
    assert st["ACCOUNT_ID"] == "123456789012"
    r = h.run("teardown.sh")  # plan, no override in env
    assert "--collection-id custom-faces" in r.stdout
    assert "--collection-id hid-kiosk-users" not in r.stdout


def test_conflicting_override_vs_state_refused(h):
    h.write_state({"COLLECTION_ID": "custom-faces"})
    r = h.run("teardown.sh", REKOGNITION_COLLECTION_ID_OVERRIDE="other-faces")
    assert r.returncode != 0
    assert "custom-faces" in r.stderr


def test_account_mismatch_refused_in_apply(h):
    h.write_state({"ACCOUNT_ID": "999999999999"})
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode != 0
    assert "999999999999" in r.stderr
    assert not any("delete" in c for c in h.joined_calls())
