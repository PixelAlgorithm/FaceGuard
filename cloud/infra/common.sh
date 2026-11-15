#!/usr/bin/env bash
# Shared helpers for cloud/infra/*.sh. Sourced, not executed.
#
# Every script defaults to PLAN mode: it prints the exact AWS commands it would run and makes NO AWS
# calls. Pass --apply to execute (only after the lead has the operator's approval). In apply mode each
# step first checks whether the resource exists (idempotent) and only creates what is missing.
# Credentials: profile hid-sandbox (~/.aws/credentials, temporary session creds) or env vars.
# Region: us-east-1 (the only sandbox region; production would be ap-south-1).
#
# Stacks (CIT-01): every name derives from HID_PREFIX (+ HID_REGION for account-global names), so a second
# stack (e.g. HID_PREFIX=hid-kiosk-staging) never shares tables, collection, tags, IAM roles or state with
# the default one. The default stack (hid-kiosk in us-east-1) keeps its historical names
# (hid_users / hid_decisions / hid_state, .state/deploy.env), so existing deployments are unaffected.
# State per stack: $STATE_DIR/<stack>.env records account, region, prefix and every resource name; later
# runs refuse an account mismatch and use the recorded names (state is the source of truth for teardown).
#
# Output hygiene (CIT-03): `run` never echoes AWS response bodies (Lambda responses carry the environment,
# i.e. every app secret). HID_VERBOSE=1 shows bodies through cloud/infra/redact.py; commands and error text
# always pass through it too.
# shellcheck disable=SC2034  # variables are used by the sourcing scripts

set -uo pipefail

DEFAULT_PREFIX="hid-kiosk"
DEFAULT_REGION="us-east-1"
HID_REGION="${HID_REGION:-$DEFAULT_REGION}"
HID_PROFILE="${HID_PROFILE:-${AWS_PROFILE:-hid-sandbox}}"
HID_PREFIX="${HID_PREFIX:-$DEFAULT_PREFIX}"
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="$(cd "$INFRA_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$CLOUD_DIR/.." && pwd)"
STATE_DIR="${HID_STATE_DIR:-$INFRA_DIR/.state}"
BUILD_DIR="${HID_BUILD_DIR:-$INFRA_DIR/build}"
ENV_FILE_SRC="${HID_ENV_FILE:-$PROJECT_ROOT/.env}"
# redact.py masks every value of this KEY=VALUE file in printed output (harmless when the file is absent)
HID_PY="${HID_PYTHON:-python3}"

if [[ ! "$HID_PREFIX" =~ ^[a-z][a-z0-9-]{1,30}[a-z0-9]$ ]]; then
  echo "FATAL: HID_PREFIX='$HID_PREFIX' must match ^[a-z][a-z0-9-]{1,30}[a-z0-9]\$" >&2
  exit 2
fi
# CI-08: the stack id below joins prefix and region with "--"; a prefix containing "--" or ending in a
# region-like suffix could otherwise alias another stack's account-global names and --confirm token
_REGION_SUFFIX_RE='-[a-z]{2}(-[a-z]+)+-[0-9]$'
if [[ "$HID_PREFIX" == *--* || "$HID_PREFIX" =~ $_REGION_SUFFIX_RE ]]; then
  echo "FATAL: HID_PREFIX='$HID_PREFIX' must not contain '--' or end in an AWS region name (set HID_REGION instead)" >&2
  exit 2
fi
if [[ ! "$HID_REGION" =~ ^[a-z]{2}(-[a-z]+)+-[0-9]$ ]]; then
  echo "FATAL: HID_REGION='$HID_REGION' is not an AWS region name" >&2
  exit 2
fi

# stack id: region-scoped for account-global resources (IAM, dashboards) and the state file. Outside
# us-east-1 it is <prefix>--<region>: prefixes never contain "--", so (prefix, region) -> stack id is injective
if [[ "$HID_REGION" == "$DEFAULT_REGION" ]]; then STACK_ID="$HID_PREFIX"; else STACK_ID="$HID_PREFIX--$HID_REGION"; fi
if [[ "$STACK_ID" == "$DEFAULT_PREFIX" ]]; then STATE_FILE="$STATE_DIR/deploy.env"; else STATE_FILE="$STATE_DIR/$STACK_ID.env"; fi

HID_TAG_KEY="Project"
HID_TAG_VALUE="$HID_PREFIX"

# deterministic resource names (teardown relies on them; recorded in state by record_stack)
COLLECTION_ID="${REKOGNITION_COLLECTION_ID_OVERRIDE:-${HID_PREFIX}-users}"
if [[ "$HID_PREFIX" == "$DEFAULT_PREFIX" ]]; then
  DDB_USERS="hid_users"; DDB_DECISIONS="hid_decisions"; DDB_STATE="hid_state"
else
  _tbl="${HID_PREFIX//-/_}"
  DDB_USERS="${_tbl}_users"; DDB_DECISIONS="${_tbl}_decisions"; DDB_STATE="${_tbl}_state"
fi
ROLE_EC2="${STACK_ID}-ec2-role"
PROFILE_EC2="${STACK_ID}-ec2-profile"
ROLE_LAMBDA="${STACK_ID}-lambda-role"
POLICY_NAME="${HID_PREFIX}-app"
SG_NAME="${HID_PREFIX}-api-sg"
API_NAME="${HID_PREFIX}-api"
LAMBDA_NAME="${HID_PREFIX}-cloud-api"
DASHBOARD="${STACK_ID}"
SSM_PREFIX="/${HID_PREFIX}"
ALARM_TOPIC_NAME="${HID_PREFIX}-security-alerts"
INSTANCE_TYPE="${HID_INSTANCE_TYPE:-t3.small}"
APP_PORT=9000
TLS_CERT_DAYS=30                # self-signed fallback certificate lifetime (re-deploy before it lapses)
APIGW_THROTTLE_RATE=50          # requests/s across the HTTP API stage (fleet heartbeats are ~0.2 rps/kiosk)
APIGW_THROTTLE_BURST=100
# alarms on SC2.6 sync alerts: name suffix | alert dimension value
ALARM_SPECS="post-hoc-revoked|ALERT_REVOKED_USER_ADMITTED log-tamper|ALERT_LOG_TAMPER sync-conflict|ALERT_SYNC_CONFLICT spoof-burst|ALERT_SPOOF_BURST"

# keys load_state accepts (anything else in a state file is ignored: values are data, never code)
STATE_KEYS="INSTANCE_ID PUBLIC_DNS FAILED_INSTANCE_ID SG_ID API_ID LAMBDA_API_ID BUCKET KMS_KEY_ID CLOUD_API_URL \
CUTOVER_AT ALARM_TOPIC_ARN ALARM_TOPIC_CREATED ARTIFACT_SHA256 DEPLOY_STAMP TLS_CERT_DAYS_ISSUED"
# names recorded per stack; loaded as REC_<KEY> and reconciled by check_stack
STATE_NAME_KEYS="ACCOUNT_ID STACK_PREFIX STACK_REGION COLLECTION_ID DDB_USERS DDB_DECISIONS DDB_STATE"

APPLY=0
unset AWS_BEARER_TOKEN_BEDROCK  # never let the coding harness token leak into AWS calls
export AWS_PAGER=""

# error codes that mean "the resource does not exist" (CIT-06: anything else is a real failure)
NOTFOUND_RE='\((ResourceNotFoundException|ResourceNotFound|NoSuchEntity|NotFoundException|NotFound|NoSuchBucket|404|ParameterNotFound|InvalidGroup\.NotFound|InvalidInstanceID\.NotFound|DashboardNotFoundError|NoSuchKey)\)'

parse_common_flags() {
  # usage: parse_common_flags "$@"; remaining args in REST[]
  REST=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --apply) APPLY=1 ;;
      --plan) APPLY=0 ;;
      --profile) HID_PROFILE="$2"; shift ;;
      --region)
        [[ "$2" == "$HID_REGION" ]] || { echo "FATAL: set HID_REGION=$2 in the environment (names derive from it)" >&2; exit 2; }
        shift ;;
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
  echo " stack=$STACK_ID region=$HID_REGION profile=$([[ -n "${AWS_ACCESS_KEY_ID:-}" ]] && echo env-vars || echo "$HID_PROFILE")"
  echo " state=$STATE_FILE"
  echo "=================================================================="
}

die() { echo "FATAL: $*" >&2; exit 2; }

# redact: stdin -> stdout with secrets masked (text or JSON; cloud/infra/redact.py, stdlib only)
redact() { "$HID_PY" "$INFRA_DIR/redact.py"; }

# temp files registered here are removed on ANY exit (CIT-10: no plaintext env left in TMPDIR)
_TMP_FILES=()
_cleanup_tmp() {
  local f
  for f in "${_TMP_FILES[@]+"${_TMP_FILES[@]}"}"; do
    if [[ -n "${HID_KEEP_RENDERED:-}" && "$f" == *"/hid-alarm-"* ]]; then continue; fi
    rm -f "$f"
  done
}
trap _cleanup_tmp EXIT
mktemp_reg() {
  # mktemp_reg VAR [name-prefix]: create a mode-600 temp file, register it for cleanup, store its path in VAR
  local _p
  _p="$(mktemp "${TMPDIR:-/tmp}/${2:-hid}.XXXXXX")" || die "mktemp failed"
  chmod 600 "$_p"
  _TMP_FILES+=("$_p")
  printf -v "$1" '%s' "$_p"
}

# Value-based redaction (cloud/infra/redact.py masks every value listed in HID_REDACT_VALUES_FILE): a 0600 temp
# copy of the SECRET entries of the source .env only (names with KEY/TOKEN/SECRET/PEPPER/PASSWORD/HMAC or *_JSON),
# so region / bucket / table names in printed commands stay readable. Removed on exit.
_secret_values_file() {
  [[ -f "$ENV_FILE_SRC" ]] || return 0
  local f
  mktemp_reg f hid-redact
  "$HID_PY" - "$ENV_FILE_SRC" >"$f" <<'PY' || return 0
import re, sys
secret = re.compile(r"(KEY|TOKEN|SECRET|PEPPER|PASSWORD|PASSWD|HMAC)|_JSON$")
for raw in open(sys.argv[1], encoding="utf-8").read().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key = line.split("=", 1)[0].strip().removeprefix("export ").strip()
    if secret.search(key):
        print(line)
PY
  export HID_REDACT_VALUES_FILE="$f"
}
_secret_values_file

_check_creds_error() {
  # $1 = stderr file. Exit 3 with a clear message on expired / missing credentials.
  if grep -qiE 'ExpiredToken|token included in the request is expired|RequestExpired' "$1"; then
    rm -f "$1"
    echo "FATAL: AWS session credentials EXPIRED. Refresh ~/.aws/credentials [$HID_PROFILE] from the" >&2
    echo "       Workshop Studio event page and re-run (the scripts are idempotent)." >&2
    exit 3
  fi
  if grep -qiE 'Unable to locate credentials|could not be found|InvalidClientTokenId' "$1"; then
    rm -f "$1"
    echo "FATAL: no valid AWS credentials (profile $HID_PROFILE / env)." >&2
    exit 3
  fi
}

# awsq <args...>: read-only query used for existence checks in APPLY mode. Prints stdout, returns rc.
awsq() {
  local err rc
  mktemp_reg err hid-err
  aws_base
  "${AWS_BASE[@]}" "$@" 2>"$err"; rc=$?
  if [[ $rc -ne 0 ]]; then _check_creds_error "$err"; AWSQ_LAST_ERR="$(head -c 600 "$err" | redact)"; fi
  rm -f "$err"
  return $rc
}

# probe <args...>: existence check. 0 = exists, 1 = NotFound-type error. Any other error ABORTS (exit 4),
# so an AccessDenied / network failure is never mistaken for "already deleted" (CIT-06). PLAN: always 0.
probe() {
  [[ $APPLY -eq 1 ]] || return 0
  local err rc
  mktemp_reg err hid-err
  aws_base
  "${AWS_BASE[@]}" "$@" >/dev/null 2>"$err"; rc=$?
  if [[ $rc -eq 0 ]]; then rm -f "$err"; return 0; fi
  _check_creds_error "$err"
  if grep -qE "$NOTFOUND_RE" "$err"; then rm -f "$err"; return 1; fi
  echo "FATAL: '$1 $2' failed with a non-NotFound error (rc=$rc); refusing to treat it as absent:" >&2
  head -c 600 "$err" | redact >&2; echo >&2
  rm -f "$err"
  exit 4
}

# run <description> -- <aws args...>: print the command; execute only in APPLY mode.
# In APPLY mode a failure STOPS the script (lead: "stop on the first failure"), except inside run_ok.
# The response body is NOT printed (CIT-03); HID_VERBOSE=1 prints it redacted.
RUN_TOLERATE=0
RUN_LAST_ERR=""
run() {
  local desc="$1"; shift
  [[ "$1" == "--" ]] && shift
  aws_base
  printf '  + %s\n    %s\n' "$desc" "$(printf '%s' "${AWS_BASE[*]} $*" | redact)"
  RUN_LAST_ERR=""
  if [[ $APPLY -eq 1 ]]; then
    local err out rc
    mktemp_reg err hid-err; mktemp_reg out hid-out
    "${AWS_BASE[@]}" "$@" >"$out" 2>"$err"; rc=$?
    if [[ -n "${HID_VERBOSE:-}" && -s "$out" ]]; then head -c 1500 "$out" | redact | sed 's/^/    | /'; echo; fi
    rm -f "$out"
    if [[ $rc -ne 0 ]]; then
      _check_creds_error "$err"
      RUN_LAST_ERR="$(head -c 600 "$err" | redact)"
      echo "    ! failed (rc=$rc): $RUN_LAST_ERR" >&2
      rm -f "$err"
      if [[ $RUN_TOLERATE -eq 1 ]]; then return $rc; fi
      echo "STOPPED on first failure. Fix the cause and re-run (scripts are idempotent)." >&2
      exit 1
    fi
    rm -f "$err"
    echo "    = ok"
  fi
  return 0
}

# run_ok <description> -- <args>: like run but tolerate any error (creation steps that may already exist).
run_ok() {
  RUN_TOLERATE=1
  run "$@" || true
  RUN_TOLERATE=0
}

# run_absent_ok <description> -- <args>: tolerate ONLY NotFound-type errors (deletes in teardown); any
# other error stops the script with the state kept (CIT-06).
run_absent_ok() {
  local rc=0
  RUN_TOLERATE=1
  run "$@" || rc=$?
  RUN_TOLERATE=0
  [[ $rc -eq 0 ]] && return 0
  if printf '%s' "$RUN_LAST_ERR" | grep -qE "$NOTFOUND_RE"; then echo "    (absent)"; return 0; fi
  echo "STOPPED: '$1' failed with a non-NotFound error; state kept, nothing reported as deleted." >&2
  exit 1
}

account_id() {
  if [[ $APPLY -eq 1 ]]; then
    local acct
    acct="$(awsq sts get-caller-identity --query Account --output text)" || die "sts get-caller-identity failed"
    [[ "$acct" =~ ^[0-9]{12}$ ]] || die "unexpected account id from sts"
    echo "$acct"
  else
    echo "${REC_ACCOUNT_ID:-<ACCOUNT_ID>}"
  fi
}

bucket_name() {
  echo "${HID_PREFIX}-$1-${HID_REGION}"
}

save_state() {
  # save_state KEY VALUE -> $STATE_FILE (resource ids only, never secrets). APPLY only. Atomic, mode 600.
  [[ $APPLY -eq 1 ]] || return 0
  [[ "$1" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "bad state key $1" >&2; return 1; }
  [[ "$2" != *$'\n'* ]] || { echo "bad state value for $1" >&2; return 1; }
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR" 2>/dev/null || true
  local f="$STATE_FILE" tmp
  tmp="$(mktemp "$STATE_DIR/.state.XXXXXX")" || die "mktemp in $STATE_DIR failed"
  chmod 600 "$tmp"
  [[ -f "$f" ]] && { grep -v "^$1=" "$f" >"$tmp" 2>/dev/null || true; }
  printf '%s=%s\n' "$1" "$2" >>"$tmp"
  mv "$tmp" "$f"
}

_is_word_in() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

clear_state_vars() {
  # CI-04: state comes ONLY from the state file. A KMS_KEY_ID / BUCKET / INSTANCE_ID ... exported in the
  # operator's shell (e.g. left over from a production session) must never act as this stack's state.
  local k
  for k in $STATE_KEYS; do unset "$k"; done
  for k in $STATE_NAME_KEYS; do unset "REC_$k"; done
  for k in $(compgen -v SES_IDENTITY_ || true); do unset "$k"; done
}

load_state() {
  # parse KEY=VALUE lines without `source` (values are data, never executed); allowlisted keys only
  local f="$STATE_FILE" k v
  clear_state_vars
  [[ -f "$f" ]] || return 0
  while IFS='=' read -r k v; do
    [[ "$k" =~ ^[A-Z_][A-Z0-9_]*$ ]] || continue
    if _is_word_in "$k" "$STATE_KEYS" || [[ "$k" == SES_IDENTITY_* ]]; then
      printf -v "$k" '%s' "$v"
    elif _is_word_in "$k" "$STATE_NAME_KEYS"; then
      printf -v "REC_$k" '%s' "$v"
    fi
  done <"$f"
  return 0
}

check_stack() {
  # check_stack ACCOUNT: refuse a state file from another account / prefix / region; adopt recorded names.
  local acct="$1" name rec cur
  if [[ -n "${REC_ACCOUNT_ID:-}" && $APPLY -eq 1 && "$REC_ACCOUNT_ID" != "$acct" ]]; then
    die "state $STATE_FILE belongs to account $REC_ACCOUNT_ID but the credentials are for $acct; refusing"
  fi
  [[ -z "${REC_STACK_PREFIX:-}" || "$REC_STACK_PREFIX" == "$HID_PREFIX" ]] \
    || die "state $STATE_FILE records prefix $REC_STACK_PREFIX, not $HID_PREFIX; refusing"
  [[ -z "${REC_STACK_REGION:-}" || "$REC_STACK_REGION" == "$HID_REGION" ]] \
    || die "state $STATE_FILE records region $REC_STACK_REGION, not $HID_REGION; refusing"
  if [[ -n "${REC_COLLECTION_ID:-}" && "$REC_COLLECTION_ID" != "$COLLECTION_ID" ]]; then
    [[ -z "${REKOGNITION_COLLECTION_ID_OVERRIDE:-}" ]] \
      || die "state records collection $REC_COLLECTION_ID but REKOGNITION_COLLECTION_ID_OVERRIDE=$REKOGNITION_COLLECTION_ID_OVERRIDE; refusing"
    echo "  note: using recorded collection $REC_COLLECTION_ID (state)"
    COLLECTION_ID="$REC_COLLECTION_ID"
  fi
  for name in DDB_USERS DDB_DECISIONS DDB_STATE; do
    rec="REC_$name"; cur="${!name}"
    if [[ -n "${!rec:-}" && "${!rec}" != "$cur" ]]; then
      echo "  note: using recorded table ${!rec} for $name (state)"
      printf -v "$name" '%s' "${!rec}"
    fi
  done
}

record_stack() {
  # record_stack ACCOUNT: persist the stack identity + resource names (APPLY only)
  save_state ACCOUNT_ID "$1"; save_state STACK_PREFIX "$HID_PREFIX"; save_state STACK_REGION "$HID_REGION"
  save_state COLLECTION_ID "$COLLECTION_ID"
  save_state DDB_USERS "$DDB_USERS"; save_state DDB_DECISIONS "$DDB_DECISIONS"; save_state DDB_STATE "$DDB_STATE"
}

init_stack() {
  # init_stack: load state, resolve account, refuse mismatches. Sets ACCOUNT_ID.
  load_state
  ACCOUNT_ID="$(account_id)" || exit 2
  check_stack "$ACCOUNT_ID"
}

render() {
  # render <template> -> stdout, substituting ${VAR} from the environment; an unresolved ${VAR} is an
  # error (CIT-15: a literal ${SSM_PREFIX} once reached an IAM policy)
  "$HID_PY" - "$1" <<'PY'
import os, re, sys
src = open(sys.argv[1]).read()
missing = sorted({m for m in re.findall(r"\$\{([A-Z0-9_]+)\}", src) if m not in os.environ})
if missing:
    sys.stderr.write("render %s: unresolved variable(s): %s\n" % (sys.argv[1], ", ".join(missing)))
    sys.exit(5)
print(re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: os.environ[m.group(1)], src), end="")
PY
}

render_to() {
  # render_to <template> <out-file>: render or stop the script
  render "$1" >"$2" || die "template $1 could not be rendered"
}

# cw_key_policy_merge <key-policy.json>: print the key policy with a statement letting CloudWatch alarms publish
# to an SNS topic encrypted with this key (kms:Decrypt + kms:GenerateDataKey*). rc 10 (nothing printed) when an
# equivalent grant is already present; any other non-zero rc = unreadable policy (caller must stop, CI-03).
CW_KMS_SID="AllowCloudWatchAlarmsToPublish"
cw_key_policy_merge() {
  "$HID_PY" - "$1" "$CW_KMS_SID" <<'PY'
import json, sys
path, sid = sys.argv[1], sys.argv[2]
try:
    doc = json.load(open(path))
except ValueError:
    sys.stderr.write("key policy is not JSON\n")
    sys.exit(5)
stmts = doc.get("Statement")
if isinstance(stmts, dict):
    stmts = [stmts]
if not isinstance(stmts, list):
    sys.stderr.write("key policy has no Statement list\n")
    sys.exit(5)
need = {"kms:Decrypt", "kms:GenerateDataKey*"}
for s in stmts:
    if not isinstance(s, dict):
        continue
    if s.get("Sid") == sid:
        sys.exit(10)
    svc = (s.get("Principal") or {}).get("Service") if isinstance(s.get("Principal"), dict) else None
    svcs = [svc] if isinstance(svc, str) else (svc or [])
    acts = s.get("Action") or []
    acts = {acts} if isinstance(acts, str) else set(acts)
    if s.get("Effect") == "Allow" and "cloudwatch.amazonaws.com" in svcs and (need <= acts or "kms:*" in acts):
        sys.exit(10)
stmts.append({"Sid": sid, "Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
              "Action": sorted(need), "Resource": "*"})
doc["Statement"] = stmts
print(json.dumps(doc, indent=2))
PY
}

tags_json() {
  echo "[{\"Key\":\"$HID_TAG_KEY\",\"Value\":\"$HID_TAG_VALUE\"},{\"Key\":\"Owner\",\"Value\":\"cloud-aws\"}]"
}
