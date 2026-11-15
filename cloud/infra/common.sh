#!/usr/bin/env bash
# Shared helpers for cloud/infra/*.sh. Sourced, not executed.
#
# Every script defaults to PLAN mode: it prints the exact AWS commands it would run and makes NO AWS
# calls. Pass --apply to execute (only after the lead has the operator's approval). In apply mode each
# step first checks whether the resource exists (idempotent) and only creates what is missing.
# Credentials: profile hid-sandbox (~/.aws/credentials, temporary session creds) or env vars.
# Region: us-east-1 (the only sandbox region; production would be ap-south-1).
# shellcheck disable=SC2034  # variables are used by the sourcing scripts

set -uo pipefail

HID_REGION="${HID_REGION:-us-east-1}"
HID_PROFILE="${HID_PROFILE:-${AWS_PROFILE:-hid-sandbox}}"
HID_PREFIX="${HID_PREFIX:-hid-kiosk}"
HID_TAG_KEY="Project"
HID_TAG_VALUE="hid-kiosk"
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="$(cd "$INFRA_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$CLOUD_DIR/.." && pwd)"
STATE_DIR="$INFRA_DIR/.state"

# deterministic resource names (teardown relies on them)
COLLECTION_ID="${REKOGNITION_COLLECTION_ID_OVERRIDE:-hid-kiosk-users}"
DDB_USERS="hid_users"
DDB_DECISIONS="hid_decisions"
DDB_STATE="hid_state"
ROLE_EC2="${HID_PREFIX}-ec2-role"
PROFILE_EC2="${HID_PREFIX}-ec2-profile"
ROLE_LAMBDA="${HID_PREFIX}-lambda-role"
POLICY_NAME="${HID_PREFIX}-app"
SG_NAME="${HID_PREFIX}-api-sg"
API_NAME="${HID_PREFIX}-api"
LAMBDA_NAME="${HID_PREFIX}-cloud-api"
DASHBOARD="${HID_PREFIX}"
SSM_PREFIX="/${HID_PREFIX}"
INSTANCE_TYPE="${HID_INSTANCE_TYPE:-t3.small}"
APP_PORT=9000

APPLY=0
unset AWS_BEARER_TOKEN_BEDROCK  # never let the coding harness token leak into AWS calls
export AWS_PAGER=""

parse_common_flags() {
  # usage: parse_common_flags "$@"; remaining args in REST[]
  REST=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=1 ;;
      --plan) APPLY=0 ;;
      --profile) HID_PROFILE="$2"; shift ;;
      --region) HID_REGION="$2"; shift ;;
      *) REST+=("$1") ;;
    esac
    shift
  done
}

aws_base() {
  # sets AWS_BASE (bash 3.2 compatible: macOS /bin/bash has no readarray or associative arrays)
  if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
    AWS_BASE=(aws --region "$HID_REGION" --output json)
  else
    AWS_BASE=(aws --profile "$HID_PROFILE" --region "$HID_REGION" --output json)
  fi
}

banner() {
  echo "=================================================================="
  echo " $1"
  echo " mode=$([[ $APPLY -eq 1 ]] && echo APPLY || echo 'PLAN (no AWS calls; re-run with --apply)')"
  echo " region=$HID_REGION profile=$([[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && echo env-vars || echo "$HID_PROFILE")"
  echo "=================================================================="
}

_check_creds_error() {
  # $1 = stderr file. Exit 3 with a clear message on expired / missing credentials.
  if grep -qiE 'ExpiredToken|token included in the request is expired|RequestExpired' "$1"; then
    echo "FATAL: AWS session credentials EXPIRED. Refresh ~/.aws/credentials [$HID_PROFILE] from the" >&2
    echo "       Workshop Studio event page and re-run (the scripts are idempotent)." >&2
    exit 3
  fi
  if grep -qiE 'Unable to locate credentials|could not be found|InvalidClientTokenId' "$1"; then
    echo "FATAL: no valid AWS credentials (profile $HID_PROFILE / env)." >&2
    exit 3
  fi
}

# awsq <args...>: read-only query used for existence checks in APPLY mode. Prints stdout, returns rc.
awsq() {
  local err rc
  err="$(mktemp)"
  aws_base
  "${AWS_BASE[@]}" "$@" 2>"$err"; rc=$?
  if [[ $rc -ne 0 ]]; then _check_creds_error "$err"; fi
  rm -f "$err"
  return $rc
}

# run <description> -- <aws args...>: print the command; execute only in APPLY mode.
# In APPLY mode a failure STOPS the script (lead: "stop on the first failure"), except inside run_ok.
RUN_TOLERATE=0
run() {
  local desc="$1"; shift
  [[ "$1" == "--" ]] && shift
  aws_base
  printf '  + %s\n    %s\n' "$desc" "${AWS_BASE[*]} $*"
  if [[ $APPLY -eq 1 ]]; then
    local err out rc
    err="$(mktemp)"; out="$(mktemp)"
    "${AWS_BASE[@]}" "$@" >"$out" 2>"$err"; rc=$?
    [[ -s "$out" ]] && head -c 1500 "$out" | sed 's/^/    | /' && echo
    rm -f "$out"
    if [[ $rc -ne 0 ]]; then
      _check_creds_error "$err"
      echo "    ! failed (rc=$rc): $(head -c 600 "$err")" >&2
      rm -f "$err"
      if [[ $RUN_TOLERATE -eq 1 ]]; then return $rc; fi
      echo "STOPPED on first failure. Fix the cause and re-run (scripts are idempotent)." >&2
      exit 1
    fi
    rm -f "$err"
  fi
  return 0
}

# run_ok <description> -- <args>: like run but tolerate "already exists / not found" style errors.
run_ok() {
  RUN_TOLERATE=1
  run "$@" || true
  RUN_TOLERATE=0
}

account_id() {
  if [[ $APPLY -eq 1 ]]; then
    awsq sts get-caller-identity --query Account --output text
  else
    echo "<ACCOUNT_ID>"
  fi
}

bucket_name() {
  echo "${HID_PREFIX}-$(account_id)-${HID_REGION}"
}

save_state() {
  # save_state KEY VALUE -> cloud/infra/.state/deploy.env (resource ids only, never secrets). APPLY only.
  [[ $APPLY -eq 1 ]] || return 0
  [[ "$1" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "bad state key $1" >&2; return 1; }
  mkdir -p "$STATE_DIR"
  local f="$STATE_DIR/deploy.env"
  touch "$f"
  grep -v "^$1=" "$f" >"$f.tmp" 2>/dev/null || true
  printf '%s=%s\n' "$1" "$2" >>"$f.tmp"
  mv "$f.tmp" "$f"
}

load_state() {
  # parse KEY=VALUE lines without `source` (values are data, never executed)
  local f="$STATE_DIR/deploy.env" k v
  [[ -f "$f" ]] || return 0
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] && printf -v "$k" '%s' "$v"
  done <"$f"
  return 0
}

render() {
  # render <template> -> stdout, substituting ${VAR} for exported HID_* style variables
  python3 - "$1" <<'PY'
import os, re, sys
src = open(sys.argv[1]).read()
print(re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), src), end="")
PY
}

tags_json() {
  echo "[{\"Key\":\"$HID_TAG_KEY\",\"Value\":\"$HID_TAG_VALUE\"},{\"Key\":\"Owner\",\"Value\":\"cloud-aws\"}]"
}
