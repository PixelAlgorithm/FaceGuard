#!/usr/bin/env bash
# =============================================================================
# teardown.sh - delete EVERYTHING the HID scripts created for ONE stack (idempotent; absent resources are
# skipped). The stack is HID_PREFIX (+ HID_REGION); names come from its state file when one exists, so a
# staging teardown can never address production tables, collection, bucket, CMK or instances (CIT-01).
# =============================================================================
# Default = PLAN (prints commands, no AWS calls). --apply executes and needs a typed confirmation:
#   --apply --confirm <stack-id>      (stack id = HID_PREFIX, or HID_PREFIX--HID_REGION outside us-east-1)
#   --keep-ses                        keep the SES identities
#   --backup                          on-demand DynamoDB backups before deleting the tables (they RETAIN data:
#                                     delete them yourself once no longer needed; DPDP erasure is incomplete
#                                     until then)
# Order: API Gateway -> Lambda -> EC2 (+wait) -> security group -> IAM roles/profiles -> DynamoDB tables ->
#        S3 bucket (all objects) -> Rekognition collection (erases every face/user vector = DPDP erasure) ->
#        SSM app env -> CloudWatch dashboard/alarms/log group -> SNS alert topic -> SES identities -> KMS CMK
#        (AWS enforces a 7-day minimum deletion wait) -> verification pass -> local build/state.
# Only NotFound-type errors count as "absent"; any other error (AccessDenied, network, throttling) stops the
# run with the state kept and a non-zero exit (CIT-06). The final verification pass must find the
# collection, tables, bucket and tagged instances gone before the local state is removed.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
KEEP_SES=0; CONFIRM=""; BACKUP=0
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-ses) KEEP_SES=1 ;;
    --backup) BACKUP=1 ;;
    --confirm) CONFIRM="${2:-}"; shift ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
banner "HID TEARDOWN of stack $STACK_ID (destructive in --apply mode)"
if [[ $APPLY -eq 1 && "$CONFIRM" != "$STACK_ID" ]]; then
  echo "FATAL: --apply deletes stack '$STACK_ID' (tables, face collection, bucket, instances)." >&2
  echo "       Re-run with: --apply --confirm $STACK_ID" >&2
  exit 2
fi
init_stack
# BUCKET comes only from this stack's state or its derived name: load_state cleared any shell value (CI-04)
BUCKET="${BUCKET:-$(bucket_name "$ACCOUNT_ID")}"
FAILED_VERIFY=0

echo "[1/12] API Gateway"
for name in "$API_NAME" "$API_NAME-lambda"; do
  if [[ $APPLY -eq 1 ]]; then
    ids="$(awsq apigatewayv2 get-apis --query "Items[?Name=='$name'].ApiId" --output text)" \
      || die "get-apis failed: ${AWSQ_LAST_ERR:-}"
    for id in $ids; do
      [[ "$id" == None ]] && continue
      run_absent_ok "delete API $name ($id)" -- apigatewayv2 delete-api --api-id "$id"
    done
  else
    run "delete API $name" -- apigatewayv2 delete-api --api-id "<id of $name>"
  fi
done

echo "[2/12] Lambda"
if probe lambda get-function --function-name "$LAMBDA_NAME"; then
  run_absent_ok "remove provisioned concurrency" -- lambda delete-provisioned-concurrency-config --function-name "$LAMBDA_NAME" --qualifier live
  run_absent_ok "delete function" -- lambda delete-function --function-name "$LAMBDA_NAME"
fi

echo "[3/12] EC2 instances tagged $HID_TAG_KEY=$HID_TAG_VALUE"
tagged_instances() {
  awsq ec2 describe-instances --filters "Name=tag:$HID_TAG_KEY,Values=$HID_TAG_VALUE" \
    "Name=instance-state-name,Values=pending,running,stopping,stopped" \
    --query 'Reservations[].Instances[].InstanceId' --output text
}
if [[ $APPLY -eq 1 ]]; then
  IDS="$(tagged_instances)" || die "describe-instances failed: ${AWSQ_LAST_ERR:-}"
  if [[ -n "$IDS" && "$IDS" != None ]]; then
    # shellcheck disable=SC2086
    run "terminate $IDS" -- ec2 terminate-instances --instance-ids $IDS
    # shellcheck disable=SC2086
    awsq ec2 wait instance-terminated --instance-ids $IDS || die "instances did not terminate: ${AWSQ_LAST_ERR:-}"
  fi
else
  run "terminate tagged instances" -- ec2 terminate-instances --instance-ids "<ids tagged $HID_TAG_KEY=$HID_TAG_VALUE>"
fi

echo "[4/12] security group $SG_NAME"
if [[ $APPLY -eq 1 ]]; then
  sgs="$(awsq ec2 describe-security-groups --filters "Name=group-name,Values=$SG_NAME" --query 'SecurityGroups[].GroupId' --output text)" \
    || die "describe-security-groups failed: ${AWSQ_LAST_ERR:-}"
  for sg in $sgs; do
    [[ "$sg" == None ]] && continue
    # RUN_TOLERATE=1: a DependencyViolation (ENI still detaching) must retry, not exit the whole teardown
    # before the Rekognition / DynamoDB / S3 erasure steps below (DPDP teardown)
    sg_gone=0
    for _ in 1 2 3 4 5 6; do
      if RUN_TOLERATE=1 run "delete $sg" -- ec2 delete-security-group --group-id "$sg"; then sg_gone=1; break; fi
      sleep 10
    done
    [[ $sg_gone -eq 1 ]] || { echo "  ! $sg not deleted (still in use?) - continuing with data erasure; re-run teardown later" >&2; FAILED_VERIFY=1; }
  done
else
  run "delete SG" -- ec2 delete-security-group --group-id "<$SG_NAME id>"
fi

echo "[5/12] IAM"
if probe iam get-instance-profile --instance-profile-name "$PROFILE_EC2"; then
  run_absent_ok "detach role from profile" -- iam remove-role-from-instance-profile --instance-profile-name "$PROFILE_EC2" --role-name "$ROLE_EC2"
  run_absent_ok "delete instance profile" -- iam delete-instance-profile --instance-profile-name "$PROFILE_EC2"
fi
for role in "$ROLE_EC2" "$ROLE_LAMBDA"; do
  if probe iam get-role --role-name "$role"; then
    run_absent_ok "delete inline policy on $role" -- iam delete-role-policy --role-name "$role" --policy-name "$POLICY_NAME"
    run_absent_ok "delete role $role" -- iam delete-role --role-name "$role"
  fi
done

echo "[6/12] DynamoDB tables (decision ledger, users, state)"
for t in "$DDB_USERS" "$DDB_DECISIONS" "$DDB_STATE"; do
  if probe dynamodb describe-table --table-name "$t"; then
    if [[ $BACKUP -eq 1 ]]; then
      run "on-demand backup of $t (RETAINS data until you delete the backup)" -- dynamodb create-backup \
        --table-name "$t" --backup-name "$t-teardown-$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    run_absent_ok "disable deletion protection on $t" -- dynamodb update-table --table-name "$t" --no-deletion-protection-enabled
    run_absent_ok "delete table $t" -- dynamodb delete-table --table-name "$t"
  fi
done

echo "[7/12] S3 bucket $BUCKET (all objects, then bucket)"
if probe s3api head-bucket --bucket "$BUCKET"; then
  run "empty bucket" -- s3 rm "s3://$BUCKET" --recursive --only-show-errors
  run_absent_ok "delete bucket" -- s3api delete-bucket --bucket "$BUCKET"
fi

echo "[8/12] Rekognition collection $COLLECTION_ID (deletes all face + user vectors)"
if probe rekognition describe-collection --collection-id "$COLLECTION_ID"; then
  run_absent_ok "delete collection" -- rekognition delete-collection --collection-id "$COLLECTION_ID"
fi

echo "[9/12] SSM SecureString $SSM_PREFIX/app-env (app secrets)"
run_absent_ok "delete parameter" -- ssm delete-parameter --name "$SSM_PREFIX/app-env"

echo "[10/12] CloudWatch + SNS alert topic"
run_absent_ok "delete dashboard" -- cloudwatch delete-dashboards --dashboard-names "$DASHBOARD"
alarm_names=()
for spec in $ALARM_SPECS; do alarm_names+=("$HID_PREFIX-${spec%%|*}"); done
run_absent_ok "delete alarms" -- cloudwatch delete-alarms --alarm-names "${alarm_names[@]}"
run_absent_ok "delete Lambda log group" -- logs delete-log-group --log-group-name "/aws/lambda/$LAMBDA_NAME"
if [[ -n "${ALARM_TOPIC_ARN:-}" && "${ALARM_TOPIC_CREATED:-0}" == 1 ]]; then
  run_absent_ok "delete SNS topic" -- sns delete-topic --topic-arn "$ALARM_TOPIC_ARN"
fi

echo "[11/12] SES identities created by ses_setup.sh"
if [[ $KEEP_SES -eq 0 && -f "$STATE_FILE" ]]; then
  while read -r addr; do
    [[ -n "$addr" ]] && run_absent_ok "delete identity $addr" -- sesv2 delete-email-identity --email-identity "$addr"
  done < <(grep '^SES_IDENTITY_' "$STATE_FILE" | cut -d= -f2-)
else
  echo "  (skipped)"
fi

echo "[12/12] KMS CMK (only if data_plane.sh --with-cmk was used)"
if [[ -n "${KMS_KEY_ID:-}" ]]; then
  run_absent_ok "delete alias" -- kms delete-alias --alias-name "alias/$HID_PREFIX"
  # CI-06: a re-run after a partial teardown finds the key already PendingDeletion; scheduling it again
  # fails with KMSInvalidStateException, which must not stop the run
  KEY_STATE=Enabled
  if [[ $APPLY -eq 1 ]]; then
    # not in $(...): awsq sets AWSQ_LAST_ERR, which a command-substitution subshell would lose
    mktemp_reg KEY_STATE_FILE hid-keystate
    if awsq kms describe-key --key-id "$KMS_KEY_ID" --query KeyMetadata.KeyState --output text >"$KEY_STATE_FILE"; then
      KEY_STATE="$(tr -d '[:space:]' <"$KEY_STATE_FILE")"
    elif printf '%s' "${AWSQ_LAST_ERR:-}" | grep -qE "$NOTFOUND_RE"; then KEY_STATE=absent
    else die "kms describe-key $KMS_KEY_ID failed: ${AWSQ_LAST_ERR:-}"; fi
  fi
  case "$KEY_STATE" in
    PendingDeletion) echo "  = key $KMS_KEY_ID already pending deletion" ;;
    absent) echo "  = key $KMS_KEY_ID absent" ;;
    *)
      rc=0
      RUN_TOLERATE=1
      run "schedule key deletion (7-day minimum wait, enforced by AWS)" -- kms schedule-key-deletion \
        --key-id "$KMS_KEY_ID" --pending-window-in-days 7 || rc=$?
      RUN_TOLERATE=0
      if [[ $rc -ne 0 ]]; then
        if printf '%s' "$RUN_LAST_ERR" | grep -q 'KMSInvalidStateException'; then
          echo "  = key $KMS_KEY_ID already scheduled for deletion (KMSInvalidStateException)"
        elif printf '%s' "$RUN_LAST_ERR" | grep -qE "$NOTFOUND_RE"; then
          echo "    (absent)"
        else
          echo "STOPPED: schedule-key-deletion failed with an unexpected error; state kept." >&2
          exit 1
        fi
      fi
      ;;
  esac
else
  echo "  (none created)"
fi

[[ $APPLY -eq 1 ]] || exit 0

echo "[verify] collection, tables, bucket and tagged instances must be gone"
verify_gone() {
  # verify_gone <label> <aws args...>: 0 when the probe reports NotFound
  if probe "${@:2}"; then echo "  ! $1 still exists" >&2; FAILED_VERIFY=1; else echo "  = $1 gone"; fi
}
verify_gone "collection $COLLECTION_ID" rekognition describe-collection --collection-id "$COLLECTION_ID"
for t in "$DDB_USERS" "$DDB_DECISIONS" "$DDB_STATE"; do
  awsq dynamodb wait table-not-exists --table-name "$t" >/dev/null 2>&1 || true
  verify_gone "table $t" dynamodb describe-table --table-name "$t"
done
verify_gone "bucket $BUCKET" s3api head-bucket --bucket "$BUCKET"
LEFT="$(tagged_instances)" || die "describe-instances failed: ${AWSQ_LAST_ERR:-}"
if [[ -n "$LEFT" && "$LEFT" != None ]]; then echo "  ! instances still present: $LEFT" >&2; FAILED_VERIFY=1; fi

if [[ $FAILED_VERIFY -ne 0 ]]; then
  echo "TEARDOWN INCOMPLETE: state kept in $STATE_FILE; fix the cause and re-run." >&2
  exit 1
fi
rm -f "$STATE_FILE" "$STATE_DIR/cloud-cert.pem"
rmdir "$STATE_DIR" 2>/dev/null || true
[[ "$STACK_ID" == "$DEFAULT_PREFIX" ]] && rm -rf "$BUILD_DIR"
echo "teardown verified: collection, tables, bucket and instances are gone; local state removed."
echo "Confirm account-wide with: cloud/infra/probe_sandbox.sh"
