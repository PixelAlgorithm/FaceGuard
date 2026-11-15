#!/usr/bin/env bash
# Download the edge-service model weights + PAD self-test fixtures into models/ (gitignored).
#
# Every file is pinned by URL *and* SHA-256; a mismatch aborts (the partial file is deleted).
# Weights are data only: nothing downloaded here is ever executed.
# Provenance + licences: edge/ml/MODELS.md.
#
# Usage (from anywhere):  bash scripts/fetch_models.sh            # fetch missing / verify existing
#                         bash scripts/fetch_models.sh --force    # re-download everything
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELS="$ROOT/models"
FIXTURES="$MODELS/fixtures"
FORCE="${1:-}"
mkdir -p "$MODELS" "$FIXTURES"

MINIVISION_COMMIT="b6d5f04ad78778917853b25c778acef6d5626d15"
MV_RAW="https://raw.githubusercontent.com/minivision-ai/Silent-Face-Anti-Spoofing/$MINIVISION_COMMIT/images/sample"

# dest | sha256 | url
FILES=$(cat <<EOF
$MODELS/MiniFASNetV2.onnx|b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907|https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV2.onnx
$MODELS/MiniFASNetV1SE.onnx|ebab7f90c7833fbccd46d3a555410e78d969db5438e169b6524be444862b3676|https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV1SE.onnx
$MODELS/retinaface_mv2.onnx|3ca44c045651cabeed1193a1fae8946ad1f3a55da8fa74b341feab5a8319f757|https://github.com/yakhyo/uniface/releases/download/weights/retinaface_mv2.onnx
$MODELS/w600k_r50.onnx|4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43|https://github.com/yakhyo/uniface/releases/download/weights/w600k_r50.onnx
$MODELS/yolox_tiny.onnx|427cc366d34e27ff7a03e2899b5e3671425c262ea2291f88bb942bc1cc70b0f7|https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_tiny.onnx
$FIXTURES/minivision_image_T1.jpg|f4455149f488f76205fdee5499ec5261d08ef6279a1cff7b778ea85405331e94|$MV_RAW/image_T1.jpg
$FIXTURES/minivision_image_F1.jpg|4b11b5d7a8a8e4a88f5f16a5426a0a7692e39e5bb45bb03b4ebe5e1606336860|$MV_RAW/image_F1.jpg
$FIXTURES/minivision_image_F2.jpg|fbbea73450ae9d9bb555c8ccac77bf39d234261fe3be4190e3ed2999690c485f|$MV_RAW/image_F2.jpg
EOF
)

sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }

fail=0
while IFS='|' read -r dest sha url; do
  [ -z "$dest" ] && continue
  name="$(basename "$dest")"
  if [ -f "$dest" ] && [ "$FORCE" != "--force" ]; then
    if [ "$(sha256_of "$dest")" = "$sha" ]; then
      echo "ok       $name"
      continue
    fi
    echo "corrupt  $name (sha256 mismatch) -> re-downloading"
  fi
  tmp="$(mktemp "$dest.XXXX.part")"
  if ! curl -fsSL --retry 3 --max-time 300 -o "$tmp" "$url"; then
    echo "FAILED   $name (download error: $url)"; rm -f "$tmp"; fail=1; continue
  fi
  got="$(sha256_of "$tmp")"
  if [ "$got" != "$sha" ]; then
    echo "FAILED   $name sha256 $got != pinned $sha"; rm -f "$tmp"; fail=1; continue
  fi
  mv "$tmp" "$dest"
  echo "fetched  $name  sha256=$sha"
done <<< "$FILES"

if [ "$fail" -ne 0 ]; then
  echo "fetch_models: one or more files failed verification" >&2
  exit 1
fi
echo "fetch_models: all files present and verified in $MODELS"
