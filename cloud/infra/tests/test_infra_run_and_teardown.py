"""CIT-03 (run never prints secrets) and CIT-06 (teardown: only NotFound means absent; anything else aborts)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import json

from .conftest import DUMMY_SECRETS

LAMBDA_CONFIG = json.dumps({"FunctionName": "hid-kiosk-cloud-api", "FunctionArn": "arn:aws:lambda:x",
                            "Environment": {"Variables": DUMMY_SECRETS}})


def _no_secret(text: str) -> None:
    for name, value in DUMMY_SECRETS.items():
        assert value not in text, f"{name} leaked"


def test_run_does_not_echo_response_bodies(h):
    h.rule("lambda", "update-function-configuration", stdout=LAMBDA_CONFIG)
    r = h.bash("APPLY=1; run 'update config' -- lambda update-function-configuration --function-name f")
    assert r.returncode == 0, r.stderr
    _no_secret(r.stdout + r.stderr)


def test_run_verbose_mode_redacts(h):
    h.rule("lambda", "update-function-configuration", stdout=LAMBDA_CONFIG)
    r = h.bash("APPLY=1; run 'update config' -- lambda update-function-configuration --function-name f",
               HID_VERBOSE="1")
    _no_secret(r.stdout + r.stderr)
    assert "hid-kiosk-cloud-api" in r.stdout  # non-secret fields still visible in verbose mode


def test_run_failure_stderr_is_redacted(h):
    h.rule("lambda", rc=254, stderr="ValidationException: KIOSK_HMAC_KEY=" + DUMMY_SECRETS["KIOSK_HMAC_KEY"])
    r = h.bash("APPLY=1; RUN_TOLERATE=1; run 'x' -- lambda update-function-configuration; echo rc=$?")
    _no_secret(r.stdout + r.stderr)
    assert "rc=254" in r.stdout


def test_deploy_lambda_apply_prints_no_secret(h):
    h.not_found("iam", "get-role", code="NoSuchEntity")
    h.not_found("lambda", "get-function")
    h.rule("lambda", "create-function", stdout=LAMBDA_CONFIG)
    h.rule("publish-version", stdout="1\n")
    h.not_found("get-alias")
    h.rule("get-apis", stdout="api123\n")
    r = h.run("deploy_lambda.sh", "--apply", "--skip-build", "--demo")
    assert r.returncode == 0, r.stdout + r.stderr
    _no_secret(r.stdout + r.stderr)
    create = [c for c in h.joined_calls() if "create-function" in c]
    assert create and "--query FunctionArn" in create[0]


def test_deploy_lambda_policy_renders_ssm_prefix(h):
    r = h.run("deploy_lambda.sh", "--skip-build", "--demo", HID_KEEP_RENDERED="1")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "${SSM_PREFIX}" not in r.stdout + r.stderr


# --------------------------------------------------------------------------- teardown (CIT-06)
def _teardown_ok_rules(h):
    h.rule("get-apis", stdout="")
    h.not_found("lambda", "get-function")
    h.rule("describe-instances", stdout="")
    h.rule("describe-security-groups", stdout="")
    h.not_found("get-instance-profile", code="NoSuchEntity")
    h.not_found("get-role", code="NoSuchEntity")


def test_teardown_apply_requires_typed_confirmation(h):
    r = h.run("teardown.sh", "--apply")
    assert r.returncode != 0
    assert "--confirm" in r.stderr
    assert not any("delete" in c for c in h.joined_calls())


def test_teardown_access_denied_aborts_and_keeps_state(h):
    h.write_state({"BUCKET": "hid-kiosk-123456789012-us-east-1"})
    _teardown_ok_rules(h)
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.rule("describe-collection", rc=254,
           stderr="An error occurred (AccessDeniedException) when calling the DescribeCollection operation")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode != 0
    assert "AccessDenied" in r.stderr
    assert (h.state_dir / "deploy.env").exists()


def test_teardown_notfound_everywhere_succeeds_and_verifies(h):
    _teardown_ok_rules(h)
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.not_found("describe-collection")
    h.not_found("ssm", "delete-parameter", code="ParameterNotFound")
    h.not_found("delete-dashboards", code="ResourceNotFound")
    h.not_found("logs", "delete-log-group")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "verified" in r.stdout.lower()


def test_teardown_existing_collection_is_deleted_and_verified(h):
    _teardown_ok_rules(h)
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.rule("describe-collection", once=True, stdout='{"FaceCount": 3}')
    h.not_found("describe-collection")  # after the delete: verification sees it gone
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    assert any("delete-collection --collection-id hid-kiosk-users" in c for c in h.joined_calls())


def test_teardown_verification_failure_keeps_state(h):
    h.write_state({"INSTANCE_ID": "i-1"})
    _teardown_ok_rules(h)
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.rule("describe-collection", stdout='{"FaceCount": 3}')  # still there after delete
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode != 0
    assert (h.state_dir / "deploy.env").exists()


def test_teardown_disables_table_deletion_protection_first(h):
    _teardown_ok_rules(h)
    h.rule("describe-table", once=True, stdout='{"Table": {}}')
    h.rule("describe-table", once=True, stdout='{"Table": {}}')
    h.rule("describe-table", once=True, stdout='{"Table": {}}')
    h.not_found("describe-table")
    h.not_found("head-bucket", code="404")
    h.not_found("describe-collection")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 0, r.stdout + r.stderr
    calls = h.joined_calls()
    i_prot = next(i for i, c in enumerate(calls) if "no-deletion-protection-enabled" in c and "hid_users" in c)
    i_del = next(i for i, c in enumerate(calls) if "delete-table --table-name hid_users" in c)
    assert i_prot < i_del


def test_teardown_expired_credentials_are_reported(h):
    # CIT-M2: the FATAL message must reach the operator (the old exists() sent it to /dev/null)
    _teardown_ok_rules(h)
    h.rule("describe-table", rc=254, stderr="An error occurred (ExpiredTokenException): The security token expired")
    r = h.run("teardown.sh", "--apply", "--confirm", "hid-kiosk")
    assert r.returncode == 3
    assert "EXPIRED" in r.stderr
