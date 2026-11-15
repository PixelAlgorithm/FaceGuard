#!/usr/bin/env bash
# =============================================================================
# ses_setup.sh - verify SES e-mail identities for the email-OTP step-up (SES sandbox).
# =============================================================================
# In the SES sandbox BOTH the sender and every recipient must be verified; AWS e-mails each address a
# verification link (valid 24 h) that its owner must click. Use consenting team members' own addresses.
# SMS OTP to India is not possible today (TRAI DLT registration) -> e-mail OTP, TOTP, staff code, card.
# Usage: cloud/infra/ses_setup.sh [--apply] --sender you@domain [--recipient a@x --recipient b@y]
#        cloud/infra/ses_setup.sh --apply --status          # show verification state (read-only)
# Then set SES_SENDER=<sender> and EMAIL_BACKEND=ses for the cloud app.
# =============================================================================
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
parse_common_flags "$@"
SENDER=""; RECIPIENTS=(); STATUS_ONLY=0
set -- "${REST[@]+"${REST[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sender) SENDER="$2"; shift ;;
    --recipient) RECIPIENTS+=("$2"); shift ;;
    --status) STATUS_ONLY=1 ;;
    *) echo "unknown arg $1"; exit 2 ;;
  esac
  shift
done
banner "HID SES identities"

if [[ $STATUS_ONLY -eq 1 ]]; then
  if [[ $APPLY -eq 1 ]]; then
    awsq sesv2 get-account --query '{production:ProductionAccessEnabled,sending:SendingEnabled,quota:SendQuota}'
    awsq sesv2 list-email-identities --query 'EmailIdentities[].{id:IdentityName,status:VerificationStatus}'
  else
    echo "  (plan) aws sesv2 get-account / list-email-identities"
  fi
  exit 0
fi
[[ -n "$SENDER" ]] || { echo "--sender required"; exit 2; }
for addr in "$SENDER" "${RECIPIENTS[@]+"${RECIPIENTS[@]}"}"; do
  [[ "$addr" == *@*.* ]] || { echo "not an e-mail address: $addr"; exit 2; }
  if [[ $APPLY -eq 1 ]] && awsq sesv2 get-email-identity --email-identity "$addr" >/dev/null 2>&1; then
    echo "  = $addr already requested/verified"
    continue
  fi
  run "verify $addr (AWS sends a link; owner must click within 24 h)" -- sesv2 create-email-identity \
    --email-identity "$addr" --tags "Key=$HID_TAG_KEY,Value=$HID_TAG_VALUE"
  save_state "SES_IDENTITY_$(printf '%s' "$addr" | tr '[:lower:]' '[:upper:]' | tr -c 'A-Z0-9' '_')" "$addr"
done
echo
echo "Next: owners click the AWS verification e-mails, then: cloud/infra/ses_setup.sh --apply --status"
