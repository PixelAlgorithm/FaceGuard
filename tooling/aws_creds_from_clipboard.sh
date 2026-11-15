#!/usr/bin/env bash
# Save AWS Workshop Studio credentials from the clipboard into ~/.aws/credentials (profile hid-sandbox).
# 1) Workshop Studio event page -> "Get AWS CLI credentials" -> copy the "Mac or Linux" block.
# 2) Run:  bash tooling/aws_creds_from_clipboard.sh
# The keys are never printed. Re-run whenever the temporary credentials expire.
set -euo pipefail
PROFILE="${PROFILE:-hid-sandbox}"
REGION="${REGION:-us-east-1}"
CLIP="$(pbpaste)"

get() {  # accepts either 'export AWS_X="v"' lines or 'aws_x = v' credentials-file lines
  local upper="$1" lower="$2"
  printf '%s\n' "$CLIP" | sed -nE \
    -e "s/^[[:space:]]*export[[:space:]]+${upper}=\"?([^\"]*)\"?[[:space:]]*$/\1/p" \
    -e "s/^[[:space:]]*${lower}[[:space:]]*=[[:space:]]*\"?([^\"]*)\"?[[:space:]]*$/\1/p" | head -1
}
AK="$(get AWS_ACCESS_KEY_ID aws_access_key_id)"
SK="$(get AWS_SECRET_ACCESS_KEY aws_secret_access_key)"
ST="$(get AWS_SESSION_TOKEN aws_session_token)"

if [[ -z "$AK" || -z "$SK" || -z "$ST" ]]; then
  echo "Clipboard does not contain the credentials block." >&2
  echo "Copy the 'Mac or Linux' block from 'Get AWS CLI credentials' and run this again." >&2
  exit 1
fi

mkdir -p ~/.aws && chmod 700 ~/.aws
CRED=~/.aws/credentials
touch "$CRED" && chmod 600 "$CRED"
# drop any old [hid-sandbox] section, keep other profiles untouched
/usr/bin/python3 - "$CRED" "$PROFILE" <<'EOF'
import sys, configparser
path, prof = sys.argv[1], sys.argv[2]
cp = configparser.RawConfigParser()
cp.read(path)
if cp.has_section(prof):
    cp.remove_section(prof)
with open(path, "w") as f:
    cp.write(f)
EOF
{
  printf '[%s]\n' "$PROFILE"
  printf 'aws_access_key_id = %s\n' "$AK"
  printf 'aws_secret_access_key = %s\n' "$SK"
  printf 'aws_session_token = %s\n' "$ST"
} >> "$CRED"
unset AK SK ST CLIP
aws configure set region "$REGION" --profile "$PROFILE"
printf '' | pbcopy   # clear the clipboard so the keys don't linger

echo "Saved profile [$PROFILE] (region $REGION). Checking it works..."
aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text
