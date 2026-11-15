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
# Note: app secrets become Lambda environment variables (encrypted at rest with aws/lambda; readable by
# principals with lambda:GetFunctionConfiguration in this single-team sandbox account).
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
PC=0; FACE=rekognition; EMAIL=ses; ROLE_ARN=""; SKIP_BUILD=0
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --pc) PC="$2"; shift ;; --face) FACE="$2"; shift ;; --email) EMAIL="$2"; shift ;;
    --role-arn) ROLE_ARN="$2"; shift ;; --skip-build) SKIP_BUILD=1 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
banner "HID cloud API on Lambda ($LAMBDA_NAME) face=$FACE email=$EMAIL pc=$PC"
load_state
ACCOUNT_ID="$(account_id)"; BUCKET="$(bucket_name)"
export HID_REGION HID_PREFIX ACCOUNT_ID BUCKET COLLECTION_ID DDB_USERS DDB_DECISIONS DDB_STATE LAMBDA_NAME

echo "[1/6] build zip (local)"
[[ $SKIP_BUILD -eq 0 ]] && "$INFRA_DIR/build_artifact.sh" --lambda | tail -2
ZIP="$INFRA_DIR/build/hid-cloud-lambda.zip"
[[ -f "$ZIP" ]] || { echo "missing $ZIP"; exit 1; }

echo "[2/6] execution role"
if [[ -z "$ROLE_ARN" ]]; then
  POLICY_FILE="$(mktemp)"; render "$INFRA_DIR/templates/app-policy.json.tmpl" >"$POLICY_FILE"
  if [[ $APPLY -eq 1 ]] && awsq iam get-role --role-name "$ROLE_LAMBDA" >/dev/null 2>&1; then
    echo "  = role exists"
  else
    run "create role" -- iam create-role --role-name "$ROLE_LAMBDA" \
      --assume-role-policy-document "file://$INFRA_DIR/templates/lambda-trust.json" --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
    [[ $APPLY -eq 1 ]] && sleep 12
  fi
  run "inline policy" -- iam put-role-policy --role-name "$ROLE_LAMBDA" --policy-name "$POLICY_NAME" --policy-document "file://$POLICY_FILE"
  rm -f "$POLICY_FILE"
  ROLE_ARN="arn:aws:iam::$ACCOUNT_ID:role/$ROLE_LAMBDA"
fi

echo "[3/6] function (python3.11, 1024 MB, 15 s)"
ENV_JSON="$(mktemp)"; chmod 600 "$ENV_JSON"
python3 "$INFRA_DIR/make_app_env.py" --out "$ENV_JSON" --format lambda --face "$FACE" --store dynamodb --email "$EMAIL" \
  --blob s3 --metrics emf_stdout --bucket "$BUCKET" --region "$HID_REGION" --collection "$COLLECTION_ID"
if [[ $APPLY -eq 1 ]] && awsq lambda get-function --function-name "$LAMBDA_NAME" >/dev/null 2>&1; then
  run "update code" -- lambda update-function-code --function-name "$LAMBDA_NAME" --zip-file "fileb://$ZIP"
  awsq lambda wait function-updated --function-name "$LAMBDA_NAME"
  run "update config" -- lambda update-function-configuration --function-name "$LAMBDA_NAME" --environment "file://$ENV_JSON"
  awsq lambda wait function-updated --function-name "$LAMBDA_NAME"
else
  run "create function" -- lambda create-function --function-name "$LAMBDA_NAME" --runtime python3.11 \
    --handler cloud.app.lambda_handler.handler --role "$ROLE_ARN" --zip-file "fileb://$ZIP" \
    --memory-size 1024 --timeout 15 --architectures x86_64 --environment "file://$ENV_JSON" \
    --tags "$HID_TAG_KEY=$HID_TAG_VALUE"
  [[ $APPLY -eq 1 ]] && awsq lambda wait function-active-v2 --function-name "$LAMBDA_NAME"
fi
rm -f "$ENV_JSON"

echo "[4/6] version + alias live"
if [[ $APPLY -eq 1 ]]; then
  VER="$(awsq lambda publish-version --function-name "$LAMBDA_NAME" --query Version --output text)"
  if awsq lambda get-alias --function-name "$LAMBDA_NAME" --name live >/dev/null 2>&1; then
    run "point alias" -- lambda update-alias --function-name "$LAMBDA_NAME" --name live --function-version "$VER"
  else
    run "create alias" -- lambda create-alias --function-name "$LAMBDA_NAME" --name live --function-version "$VER"
  fi
else
  run "publish version" -- lambda publish-version --function-name "$LAMBDA_NAME"
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
      --tags "$HID_TAG_KEY=$HID_TAG_VALUE" --query ApiId --output text)"
  fi
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
echo "  verify: cloud/.venv/bin/python -m cloud.tools.smoke --base $URL"
