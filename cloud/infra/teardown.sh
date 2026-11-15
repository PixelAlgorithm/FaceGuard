#!/usr/bin/env bash
# =============================================================================
# teardown.sh - delete EVERYTHING the HID scripts created (idempotent; missing resources are skipped).
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes.
# Order: API Gateway -> Lambda -> EC2 (+wait) -> security group -> IAM roles/profiles -> DynamoDB tables ->
#        S3 bucket (all objects) -> Rekognition collection (erases every face/user vector = DPDP erasure) ->
#        CloudWatch dashboard/alarm/log group -> SES identities (unless --keep-ses) -> KMS CMK (only if one was
#        created; AWS enforces a 7-day minimum deletion wait) -> local build/state.
# Afterwards run cloud/infra/probe_sandbox.sh to confirm nothing tagged Project=hid-kiosk remains.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
KEEP_SES=0
for a in "${REST[@]+"${REST[@]}"}"; do
  case "$a" in --keep-ses) KEEP_SES=1 ;; *) echo "unknown arg $a"; exit 2 ;; esac
done
banner "HID TEARDOWN (destructive in --apply mode)"
load_state
BUCKET="${BUCKET:-$(bucket_name)}"

exists() { [[ $APPLY -eq 0 ]] || awsq "$@" >/dev/null 2>&1; }

echo "[1/11] API Gateway"
for name in "$API_NAME" "$API_NAME-lambda"; do
  if [[ $APPLY -eq 1 ]]; then
    for id in $(awsq apigatewayv2 get-apis --query "Items[?Name=='$name'].ApiId" --output text); do
      run "delete API $name ($id)" -- apigatewayv2 delete-api --api-id "$id"
    done
  else
    run "delete API $name" -- apigatewayv2 delete-api --api-id "<id of $name>"
  fi
done

echo "[2/11] Lambda"
if exists lambda get-function --function-name "$LAMBDA_NAME"; then
  run_ok "remove provisioned concurrency" -- lambda delete-provisioned-concurrency-config --function-name "$LAMBDA_NAME" --qualifier live
  run "delete function" -- lambda delete-function --function-name "$LAMBDA_NAME"
fi

echo "[3/11] EC2 instances tagged $HID_TAG_KEY=$HID_TAG_VALUE"
if [[ $APPLY -eq 1 ]]; then
  IDS="$(awsq ec2 describe-instances --filters "Name=tag:$HID_TAG_KEY,Values=$HID_TAG_VALUE" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' --output text)"
  if [[ -n "$IDS" ]]; then
    # shellcheck disable=SC2086
    run "terminate $IDS" -- ec2 terminate-instances --instance-ids $IDS
    # shellcheck disable=SC2086
    awsq ec2 wait instance-terminated --instance-ids $IDS
  fi
else
  run "terminate tagged instances" -- ec2 terminate-instances --instance-ids "<ids tagged $HID_TAG_KEY=$HID_TAG_VALUE>"
fi

echo "[4/11] security group $SG_NAME"
if [[ $APPLY -eq 1 ]]; then
  for sg in $(awsq ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[].GroupId' --output text); do
    # RUN_TOLERATE=1: a DependencyViolation (ENI still detaching) must retry, not exit the whole teardown
    # before the Rekognition / DynamoDB / S3 erasure steps below (DPDP teardown)
    sg_gone=0
    for _ in 1 2 3 4 5 6; do
      if RUN_TOLERATE=1 run "delete $sg" -- ec2 delete-security-group --group-id "$sg"; then sg_gone=1; break; fi
      sleep 10
    done
    [[ $sg_gone -eq 1 ]] || echo "  ! $sg not deleted (still in use?) - continuing with data erasure; re-run teardown later" >&2
  done
else
  run "delete SG" -- ec2 delete-security-group --group-id "<$SG_NAME id>"
fi

echo "[5/11] IAM"
if exists iam get-instance-profile --instance-profile-name "$PROFILE_EC2"; then
  run_ok "detach role from profile" -- iam remove-role-from-instance-profile --instance-profile-name "$PROFILE_EC2" --role-name "$ROLE_EC2"
  run "delete instance profile" -- iam delete-instance-profile --instance-profile-name "$PROFILE_EC2"
fi
for role in "$ROLE_EC2" "$ROLE_LAMBDA"; do
  if exists iam get-role --role-name "$role"; then
    run_ok "delete inline policy on $role" -- iam delete-role-policy --role-name "$role" --policy-name "$POLICY_NAME"
    run "delete role $role" -- iam delete-role --role-name "$role"
  fi
done

echo "[6/11] DynamoDB tables (decision ledger, users, state)"
for t in "$DDB_USERS" "$DDB_DECISIONS" "$DDB_STATE"; do
  if exists dynamodb describe-table --table-name "$t"; then
    run "delete table $t" -- dynamodb delete-table --table-name "$t"
  fi
done

echo "[7/11] S3 bucket $BUCKET (all objects, then bucket)"
if exists s3api head-bucket --bucket "$BUCKET"; then
  run "empty bucket" -- s3 rm "s3://$BUCKET" --recursive --only-show-errors
  run "delete bucket" -- s3api delete-bucket --bucket "$BUCKET"
fi

echo "[8/11] Rekognition collection $COLLECTION_ID (deletes all face + user vectors)"
if exists rekognition describe-collection --collection-id "$COLLECTION_ID"; then
  run "delete collection" -- rekognition delete-collection --collection-id "$COLLECTION_ID"
fi

echo "[8b] SSM SecureString $SSM_PREFIX/app-env (app secrets)"
run_ok "delete parameter" -- ssm delete-parameter --name "$SSM_PREFIX/app-env"

echo "[9/11] CloudWatch"
run_ok "delete dashboard" -- cloudwatch delete-dashboards --dashboard-names "$DASHBOARD"
run_ok "delete alarm" -- cloudwatch delete-alarms --alarm-names "$HID_PREFIX-post-hoc-revoked"
run_ok "delete Lambda log group" -- logs delete-log-group --log-group-name "/aws/lambda/$LAMBDA_NAME"

echo "[10/11] SES identities created by ses_setup.sh"
if [[ $KEEP_SES -eq 0 && -f "$STATE_DIR/deploy.env" ]]; then
  grep '^SES_IDENTITY_' "$STATE_DIR/deploy.env" | cut -d= -f2- | while read -r addr; do
    run_ok "delete identity $addr" -- sesv2 delete-email-identity --email-identity "$addr"
  done
else
  echo "  (skipped)"
fi

echo "[11/11] KMS CMK (only if data_plane.sh --with-cmk was used)"
if [[ -n "${KMS_KEY_ID:-}" ]]; then
  run_ok "delete alias" -- kms delete-alias --alias-name "alias/$HID_PREFIX"
  run "schedule key deletion (7-day minimum wait, enforced by AWS)" -- kms schedule-key-deletion --key-id "$KMS_KEY_ID" --pending-window-in-days 7
else
  echo "  (none created)"
fi

if [[ $APPLY -eq 1 ]]; then
  rm -rf "$STATE_DIR" "$INFRA_DIR/build"
  echo "local state + build removed. Confirm with: cloud/infra/probe_sandbox.sh"
fi
