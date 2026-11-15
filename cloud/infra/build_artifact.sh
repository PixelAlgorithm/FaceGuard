#!/usr/bin/env bash
# =============================================================================
# build_artifact.sh - package the cloud API for EC2 (tgz) or Lambda (zip). LOCAL ONLY, no AWS calls.
# =============================================================================
# Contents:
#   app/cloud/            cloud API code (no tests/tools except fakeimg)
#   app/edge/policy/*.py  vendor-copied shared policy code (evaluate_schedule) - same code as the kiosk
#   app/edge/offline/*.py vendor-copied offline helpers (bundle verifier, signing)
#   app/edge/auth/        EXPLICIT allowlist: __init__.py, rbac.py, tokens.py (stdlib-only RBAC catalog and
#                         credential formats; never the edge's staff store, sessions or passwords)
#   app/config/           thresholds.yaml + schedule seeds
#   app/scripts/sign_bundle.py  demo card-hash recompute + documented-code hygiene used by the cloud
#   vendor/               uv.lock-pinned deps installed with --require-hashes (CIT-16) as manylinux x86_64
#                         CPython 3.11 wheels
# The stage must import (`import edge.auth.rbac, edge.auth.tokens, cloud.app.main`) or the build FAILS.
# Usage: cloud/infra/build_artifact.sh [--lambda] [--stage-only]
#   --stage-only   build + import-check the code stage only (no wheel download, no package; used by tests)
# Output: $HID_BUILD_DIR (default cloud/infra/build)/hid-cloud.tgz | hid-cloud-lambda.zip (+ .sha256)
# HID_SOURCE_ROOT overrides the project root that is packaged (tests).
# =============================================================================
set -euo pipefail
INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${HID_SOURCE_ROOT:-$(cd "$INFRA_DIR/../.." && pwd)}"
CLOUD_DIR="$ROOT/cloud"
MODE="ec2"; STAGE_ONLY=0
for a in "$@"; do
  case "$a" in
    --lambda) MODE="lambda" ;;
    --stage-only) STAGE_ONLY=1 ;;
    *) echo "unknown arg $a" >&2; exit 2 ;;
  esac
done
EDGE_AUTH_ALLOWLIST="__init__.py rbac.py tokens.py"
LAMBDA_RUNTIME_PROVIDED="boto3 botocore s3transfer jmespath uvloop watchfiles websockets httptools"
PY_CHECK="${HID_CHECK_PYTHON:-$CLOUD_DIR/.venv/bin/python}"

BUILD="${HID_BUILD_DIR:-$INFRA_DIR/build}"
STAGE="$BUILD/stage-$MODE"
case "$STAGE" in */build/stage-ec2|*/build/stage-lambda) ;; *) echo "unexpected stage path $STAGE" >&2; exit 2 ;; esac
rm -rf "$STAGE"
mkdir -p "$STAGE/app/cloud" "$STAGE/app/edge/auth" "$STAGE/app/config" "$STAGE/app/scripts" "$STAGE/vendor"

echo "[1/5] code -> $STAGE/app"
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
for f in $EDGE_AUTH_ALLOWLIST; do
  [[ -f "$ROOT/edge/auth/$f" ]] || { echo "edge/auth/$f missing - cannot ship (cloud RBAC needs edge.auth.rbac)" >&2; exit 1; }
  cp "$ROOT/edge/auth/$f" "$STAGE/app/edge/auth/"
done
cp "$ROOT/config/thresholds.yaml" "$ROOT"/config/*.json "$STAGE/app/config/"
if [[ -f "$ROOT/scripts/sign_bundle.py" ]]; then cp "$ROOT/scripts/sign_bundle.py" "$STAGE/app/scripts/"; fi
test -f "$STAGE/app/edge/policy/schedule.py" || { echo "edge/policy/schedule.py missing - cannot ship" >&2; exit 1; }

echo "[2/5] stage import check (edge.auth.rbac, edge.auth.tokens, cloud.app.main)"
[[ -x "$PY_CHECK" ]] || { echo "no Python for the import check at $PY_CHECK (uv sync --project cloud)" >&2; exit 1; }
# -s: no user site; PYTHONPATH = the stage only, so a module missing from the stage is not found elsewhere
if ! (cd "$STAGE" && env -i PATH="/usr/bin:/bin" HOME="$STAGE" PYTHONPATH="$STAGE/app" PYTHONDONTWRITEBYTECODE=1 \
      "$PY_CHECK" -s - "$STAGE/app" <<'PY'
import importlib, sys
stage = sys.argv[1]
for name in ("edge.auth.rbac", "edge.auth.tokens", "cloud.app.main"):
    mod = importlib.import_module(name)
    if not str(mod.__file__).startswith(stage):
        sys.exit(f"{name} resolved outside the stage: {mod.__file__}")
print("      import check ok")
PY
); then
  echo "stage import check FAILED: the artifact would not start (missing edge/auth/rbac.py or a dependency)" >&2
  exit 1
fi
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +
if [[ $STAGE_ONLY -eq 1 ]]; then echo "stage only: $STAGE"; exit 0; fi

command -v uv >/dev/null || { echo "uv not found" >&2; exit 2; }
echo "[3/5] hash-pinned requirements from cloud/uv.lock"
REQ="$BUILD/requirements-$MODE.txt"
EXPORT_ARGS=(--frozen --no-dev --no-emit-project --quiet)
[[ $MODE == lambda ]] && EXPORT_ARGS+=(--group lambda)
(cd "$CLOUD_DIR" && uv export "${EXPORT_ARGS[@]}" >"$REQ")
if [[ $MODE == lambda ]]; then
  # boto3/botocore are provided by the Lambda runtime; uvicorn's native extras are unused there.
  # Whole requirement blocks (incl. their --hash lines) are dropped so --require-hashes still holds.
  # shellcheck disable=SC2086
  python3 "$INFRA_DIR/filter_requirements.py" $LAMBDA_RUNTIME_PROVIDED <"$REQ" >"$REQ.tmp"
  mv "$REQ.tmp" "$REQ"
fi
grep -q -- '--hash=sha256:' "$REQ" || { echo "requirements carry no hashes - refusing to vendor" >&2; exit 1; }
echo "      $(grep -c '==' "$REQ") pinned packages (sha256-verified)"

echo "[4/5] vendor wheels for x86_64-manylinux2014 / cp311 (--require-hashes)"
uv pip install --quiet --require-hashes --target "$STAGE/vendor" --python-platform x86_64-manylinux2014 \
  --python-version 3.11 --only-binary :all: -r "$REQ"
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +

echo "[5/5] package"
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
