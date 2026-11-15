#!/usr/bin/env bash
# =============================================================================
# deploy_lambda.sh - ALTERNATIVE host: Lambda (python3.11, zip) behind an API Gateway HTTP API.
# Not recommended for the 2 s path (cold starts; see cloud/SANDBOX.md §6) - use only if EC2 is denied.
# =============================================================================
# Default = PLAN. --apply executes (lead approval required).
#   --pc N          provisioned concurrency on alias "live" (needs >= 10 unreserved account concurrency)
#   --face/--email  rekognition|disabled / ses|disabled ; store is always DynamoDB (Lambda disk is ephemeral)
#   --role-arn ARN  use a PRE-PROVISIONED execution role (no IAM writes)
#   --skip-build
#   --seed-schedule config/<file>.json | --demo   (mandatory, as in deploy_ec2.sh; CIT-05)
# Note: app secrets become Lambda environment variables (encrypted at rest with aws/lambda; readable by
# principals with lambda:GetFunctionConfiguration in this single-team sandbox account). Every Lambda call
# that returns the configuration is run with --query FunctionArn and `run` never prints response bodies, so
# the secrets never reach the terminal or a CI log (CIT-03). Production: move them to SSM / Secrets Manager.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
PC=0; FACE=rekognition; EMAIL=ses; ROLE_ARN=""; SKIP_BUILD=0; SEED_SCHEDULE=""; DEMO=0
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pc) PC="$2"; shift ;; --face) FACE="$2"; shift ;; --email) EMAIL="$2"; shift ;;
    --role-arn) ROLE_ARN="${2:-}"; shift ;; --skip-build) SKIP_BUILD=1 ;;
    --seed-schedule) SEED_SCHEDULE="${2:-}"; shift ;; --demo) DEMO=1 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
case "$FACE" in rekognition|disabled) ;; *) die "--face must be rekognition|disabled" ;; esac
case "$EMAIL" in ses|disabled) ;; *) die "--email must be ses|disabled" ;; esac
[[ "$PC" =~ ^[0-9]+$ ]] || die "--pc must be a number"
[[ -z "$ROLE_ARN" || "$ROLE_ARN" =~ ^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$ ]] || die "bad --role-arn"
if [[ -z "$SEED_SCHEDULE" ]]; then
  [[ $DEMO -eq 1 ]] || die "a seed is required: --seed-schedule config/<file>.json, or --demo (config/schedule.demo.json)"
  SEED_SCHEDULE="config/schedule.demo.json"
fi
banner "HID cloud API on Lambda ($LAMBDA_NAME) face=$FACE email=$EMAIL pc=$PC seed=$SEED_SCHEDULE"
init_stack
BUCKET="$(bucket_name "$ACCOUNT_ID")"
record_stack "$ACCOUNT_ID"
if [[ -n "${KMS_KEY_ID:-}" ]]; then KMS_KEY_ARN="arn:aws:kms:$HID_REGION:$ACCOUNT_ID:key/$KMS_KEY_ID"
else KMS_KEY_ARN="arn:aws:kms:$HID_REGION:$ACCOUNT_ID:key/00000000-0000-0000-0000-000000000000"; fi
SES_FROM="$("$HID_PY" "$INFRA_DIR/make_app_env.py" --resolve-sender --env-file "$ENV_FILE_SRC")" || exit 1
[[ "$EMAIL" == ses && -n "$SES_FROM" ]] && SES_FROM_ADDRESS="$SES_FROM" || SES_FROM_ADDRESS="no-sender@invalid"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET COLLECTION_ID DDB_USERS DDB_DECISIONS DDB_STATE LAMBDA_NAME SSM_PREFIX \
  SES_FROM_ADDRESS KMS_KEY_ARN

echo "[1/6] build zip (local)"
if [[ $SKIP_BUILD -eq 0 ]]; then "$INFRA_DIR/build_artifact.sh" --lambda | tail -3 || die "artifact build failed"; fi
ZIP="$BUILD_DIR/hid-cloud-lambda.zip"
[[ -f "$ZIP" ]] || die "missing $ZIP"

echo "[2/6] execution role"
if [[ -z "$ROLE_ARN" ]]; then
  mktemp_reg POLICY_FILE hid-policy; render_to "$INFRA_DIR/templates/app-policy.json.tmpl" "$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && probe iam get-role --role-name "$ROLE_LAMBDA"; then
    echo "  = role exists"
  else
    run "create role" -- iam create-role --role-name "$ROLE_LAMBDA" \
      --assume-role-policy-document "file://$INFRA_DIR/templates/lambda-trust.json" --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
    [[ $APPLY -eq 1 ]] && sleep 12
  fi
  run "inline policy" -- iam put-role-policy --role-name "$ROLE_LAMBDA" --policy-name "$POLICY_NAME" --policy-document "file://$POLICY_FILE"
  ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ROLE_LAMBDA"
fi

echo "[3/6] function (python3.11, 1024 MB, 15 s)"
mktemp_reg ENV_JSON hid-lambdaenv
DEMO_ARG=(); [[ $DEMO -eq 1 ]] && DEMO_ARG=(--demo)
KEY_ARG=(); [[ -n "${KMS_KEY_ID:-}" ]] && KEY_ARG=(--kms-key-id "$KMS_KEY_ID")
"$HID_PY" "$INFRA_DIR/make_app_env.py" --env-file "$ENV_FILE_SRC" --out "$ENV_JSON" --format lambda --face "$FACE" \
  --store dynamodb --email "$EMAIL" --blob s3 --metrics emf_stdout --bucket "$BUCKET" --region "$HID_REGION" \
  --collection "$COLLECTION_ID" --ddb-users "$DDB_USERS" --ddb-decisions "$DDB_DECISIONS" --ddb-state "$DDB_STATE" \
  --seed-schedule "$SEED_SCHEDULE" "${DEMO_ARG[@]+"${DEMO_ARG[@]}"}" "${KEY_ARG[@]+"${KEY_ARG[@]}"}" || exit 1
ARN_ONLY=(--query FunctionArn --output text)  # responses carry Environment.Variables = every secret
if [[ $APPLY -eq 1 ]] && probe lambda get-function --function-name "$LAMBDA_NAME"; then
  run "update code" -- lambda update-function-code --function-name "$LAMBDA_NAME" --zip-file "fileb://$ZIP" "${ARN_ONLY[@]}"
  awsq lambda wait function-updated --function-name "$LAMBDA_NAME" || die "function update did not settle"
  run "update config" -- lambda update-function-configuration --function-name "$LAMBDA_NAME" \
    --environment "file://$ENV_JSON" "${ARN_ONLY[@]}"
  awsq lambda wait function-updated --function-name "$LAMBDA_NAME" || die "function update did not settle"
else
  run "create function" -- lambda create-function --function-name "$LAMBDA_NAME" --runtime python3.11 \
    --handler cloud.app.lambda_handler.handler --role "$ROLE_ARN" --zip-file "fileb://$ZIP" \
    --memory-size 1024 --timeout 15 --architectures x86_64 --environment "file://$ENV_JSON" \
    --tags "$HID_TAG_KEY=$HID_TAG_VALUE" "${ARN_ONLY[@]}"
  if [[ $APPLY -eq 1 ]]; then awsq lambda wait function-active-v2 --function-name "$LAMBDA_NAME" || die "function not active"; fi
fi
rm -f "$ENV_JSON"

# health_check_version VER: invoke the published version with an API Gateway v2 GET /v1/health event and
# require statusCode 200 BEFORE alias `live` moves (a version that cannot start never takes traffic; the old
# version keeps serving). The response body is parsed, never printed.
health_check_version() {
  local ver="$1" ev resp
  mktemp_reg ev hid-health-event; mktemp_reg resp hid-health-resp
  "$HID_PY" "$INFRA_DIR/make_app_env.py" --health-event "$ev" || die "could not write the /v1/health test event"
  run_ok "health check: version $ver answers GET /v1/health" -- lambda invoke --function-name "$LAMBDA_NAME" \
    --qualifier "$ver" --cli-binary-format raw-in-base64-out --payload "file://$ev" "$resp"
  [[ $APPLY -eq 1 ]] || return 0
  "$HID_PY" "$INFRA_DIR/make_app_env.py" --check-health-response "$resp" \
    || die "version $ver did not answer GET /v1/health with 200; alias live NOT updated (the previous version keeps serving). Inspect: aws logs tail /aws/lambda/$LAMBDA_NAME"
  echo "    = version $ver healthy"
  rm -f "$resp"
}

echo "[4/6] version + health check + alias live"
if [[ $APPLY -eq 1 ]]; then
  VER="$(awsq lambda publish-version --function-name "$LAMBDA_NAME" --query Version --output text)" \
    || die "publish-version failed: ${AWSQ_LAST_ERR:-}"
  [[ "$VER" =~ ^[0-9]+$ ]] || die "unexpected version from publish-version"
  health_check_version "$VER"
  if probe lambda get-alias --function-name "$LAMBDA_NAME" --name live; then
    run "point alias" -- lambda update-alias --function-name "$LAMBDA_NAME" --name live --function-version "$VER"
  else
    run "create alias" -- lambda create-alias --function-name "$LAMBDA_NAME" --name live --function-version "$VER"
  fi
else
  run "publish version" -- lambda publish-version --function-name "$LAMBDA_NAME"
  health_check_version "<ver>"
  run "alias live" -- lambda create-alias --function-name "$LAMBDA_NAME" --name live --function-version "<ver>"
fi
ALIAS_ARN="arn:aws:lambda:$HID_REGION:$ACCOUNT_ID:function:$LAMBDA_NAME:live"
if [[ "$PC" -gt 0 ]]; then
  run_ok "provisioned concurrency $PC" -- lambda put-provisioned-concurrency-config --function-name "$LAMBDA_NAME" \
    --qualifier live --provisioned-concurrent-executions "$PC"
fi

echo "[5/6] API Gateway HTTP API -> alias"
if [[ $APPLY -eq 1 ]]; then
  API_ID="$(awsq apigatewayv2 get-apis --query "Items[?Name=='$API_NAME-lambda'].ApiId | [0]" --output text)"
  if [[ "$API_ID" == "None" || -z "$API_ID" ]]; then
    API_ID="$(awsq apigatewayv2 create-api --name "$API_NAME-lambda" --protocol-type HTTP --target "$ALIAS_ARN" \
      --tags "$HID_TAG_KEY=$HID_TAG_VALUE" --query ApiId --output text)" || die "create-api failed: ${AWSQ_LAST_ERR:-}"
  fi
  [[ -n "$API_ID" && "$API_ID" != None ]] || die "no API id"
  save_state LAMBDA_API_ID "$API_ID"
  run_ok "allow API Gateway to invoke" -- lambda add-permission --function-name "$LAMBDA_NAME" --qualifier live \
    --statement-id apigw-invoke --action lambda:InvokeFunction --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$HID_REGION:$ACCOUNT_ID:$API_ID/*"
  URL="https://$API_ID.execute-api.$HID_REGION.amazonaws.com"
else
  run "quick-create HTTP API" -- apigatewayv2 create-api --name "$API_NAME-lambda" --protocol-type HTTP --target "$ALIAS_ARN"
  run "invoke permission" -- lambda add-permission --function-name "$LAMBDA_NAME" --qualifier live --statement-id apigw-invoke \
    --action lambda:InvokeFunction --principal apigateway.amazonaws.com
  URL="https://<api-id>.execute-api.$HID_REGION.amazonaws.com"
fi

echo "[6/6] result"
[[ $APPLY -eq 1 ]] && save_state CLOUD_API_URL "$URL"
echo "  CLOUD_API_URL=$URL   (first call after idle pays a cold start; heartbeats every 5 s keep one env warm)"
echo "  verify: cloud/.venv/bin/python -m cloud.tools.smoke_noface --live --base $URL"
