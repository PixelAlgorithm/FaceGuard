#!/usr/bin/env bash
# =============================================================================
# build_artifact.sh - package the cloud API for EC2 (tgz) or Lambda (zip). LOCAL ONLY, no AWS calls.
# =============================================================================
# Contents:
#   app/cloud/            cloud API code (no tests/tools)
#   app/edge/policy/*.py  vendor-copied shared policy code (evaluate_schedule) - same code as the kiosk
#   app/edge/offline/*.py vendor-copied offline helpers (if any)
#   app/config/           thresholds.yaml + schedule.example.json (seed)
#   vendor/               pinned deps (uv.lock) as manylinux x86_64 CPython 3.11 wheels
# Usage: cloud/infra/build_artifact.sh [--lambda]
# Output: cloud/infra/build/hid-cloud.tgz | cloud/infra/build/hid-cloud-lambda.zip (+ .sha256)
# =============================================================================
set -euo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLOUD_DIR="$(cd "$INFRA_DIR/.." && pwd)"
ROOT="$(cd "$CLOUD_DIR/.." && pwd)"
MODE="ec2"
[[ "${1:-}" == "--lambda" ]] && MODE="lambda"
command -v uv >/dev/null || { echo "uv not found"; exit 2; }

BUILD="$INFRA_DIR/build"
STAGE="$BUILD/stage-$MODE"
rm -rf "$STAGE"
mkdir -p "$STAGE/app/cloud" "$STAGE/app/edge" "$STAGE/app/config" "$STAGE/vendor"

echo "[1/4] code -> $STAGE/app"
cp "$CLOUD_DIR/__init__.py" "$STAGE/app/cloud/"
rsync -a --exclude '__pycache__' "$CLOUD_DIR/app/" "$STAGE/app/cloud/app/"
mkdir -p "$STAGE/app/cloud/tools"
cp "$CLOUD_DIR/tools/__init__.py" "$CLOUD_DIR/tools/fakeimg.py" "$STAGE/app/cloud/tools/"
cp "$ROOT/edge/__init__.py" "$STAGE/app/edge/"
for pkg in policy offline; do
  if [[ -d "$ROOT/edge/$pkg" ]]; then
    mkdir -p "$STAGE/app/edge/$pkg"
    find "$ROOT/edge/$pkg" -maxdepth 1 -name '*.py' -exec cp {} "$STAGE/app/edge/$pkg/" \;
  fi
done
cp "$ROOT/config/thresholds.yaml" "$ROOT"/config/*.json "$STAGE/app/config/"
mkdir -p "$STAGE/app/scripts"
[[ -f "$ROOT/scripts/sign_bundle.py" ]] && cp "$ROOT/scripts/sign_bundle.py" "$STAGE/app/scripts/"  # demo card hashes
test -f "$STAGE/app/edge/policy/schedule.py" || { echo "edge/policy/schedule.py missing - cannot ship"; exit 1; }

echo "[2/4] pinned requirements from cloud/uv.lock"
REQ="$BUILD/requirements-$MODE.txt"
EXPORT_ARGS=(--frozen --no-dev --no-hashes --no-emit-project --quiet)
[[ $MODE == lambda ]] && EXPORT_ARGS+=(--group lambda)
(cd "$CLOUD_DIR" && uv export "${EXPORT_ARGS[@]}" >"$REQ")
if [[ $MODE == lambda ]]; then
  # boto3/botocore are provided by the Lambda runtime; uvicorn's native extras are unused there
  grep -viE '^(boto3|botocore|s3transfer|jmespath|uvloop|watchfiles|websockets|httptools)==' "$REQ" >"$REQ.tmp"
  mv "$REQ.tmp" "$REQ"
fi
echo "      $(grep -c '==' "$REQ") pinned packages"

echo "[3/4] vendor wheels for x86_64-manylinux2014 / cp311"
uv pip install --quiet --target "$STAGE/vendor" --python-platform x86_64-manylinux2014 \
  --python-version 3.11 --only-binary :all: -r "$REQ"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo "[4/4] package"
if [[ $MODE == ec2 ]]; then
  OUT="$BUILD/hid-cloud.tgz"
  tar -C "$STAGE" -czf "$OUT" app vendor
else
  OUT="$BUILD/hid-cloud-lambda.zip"
  rm -f "$OUT"
  # Lambda: everything at the zip root (code + deps), handler cloud.app.lambda_handler.handler
  (cd "$STAGE/vendor" && zip -qr9 "$OUT" .)
  (cd "$STAGE/app" && zip -qr9 "$OUT" .)
fi
shasum -a 256 "$OUT" | tee "$OUT.sha256"
ls -lh "$OUT"
