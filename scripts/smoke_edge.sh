#!/usr/bin/env bash
# End-to-end curl smoke test against a running edge (default http://127.0.0.1:8000):
# health -> session/start -> probe -> frames (synthetic public-domain face, simulated flash) -> decision.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EDGE="${EDGE_URL:-http://127.0.0.1:8000}"
KIOSK="${KIOSK_ID:-KIOSK_MAIN_01}"
PY="$ROOT/edge/.venv/bin/python"
OUT="$(mktemp -d /tmp/edge_smoke.XXXX)"

echo "== health";  curl -fsS "$EDGE/v1/health" | "$PY" -m json.tool | head -30
echo "== session/start"
curl -fsS -X POST "$EDGE/v1/session/start" -H 'Content-Type: application/json' \
  -d "{\"kiosk_id\":\"$KIOSK\",\"client\":{\"camera_label\":\"FaceTime HD Camera\",\"user_agent\":\"curl\",\"screen\":{}},\"flash_enabled\":true}" \
  > "$OUT/session.json"
cat "$OUT/session.json"; echo
ATT="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["attempt_id"])' "$OUT/session.json")"
(cd "$ROOT" && "$PY" -m edge.synth "$OUT" < "$OUT/session.json" > /dev/null)
echo "== probe ($ATT): face-lock frame -> early cloud match (expect 202 started|skipped)"
curl -sS -X POST "$EDGE/v1/attempt/$ATT/probe" -F "probe=@$OUT/frame_0.jpg;type=image/jpeg" -w '  HTTP %{http_code}\n'
echo "== second probe (expect 409 INVALID_STATE)"
curl -sS -X POST "$EDGE/v1/attempt/$ATT/probe" -F "probe=@$OUT/frame_0.jpg;type=image/jpeg" -w '  HTTP %{http_code}\n'
echo "== frames ($ATT)"
curl -fsS -X POST "$EDGE/v1/attempt/$ATT/frames" \
  -F "frame_0=@$OUT/frame_0.jpg;type=image/jpeg" -F "frame_1=@$OUT/frame_1.jpg;type=image/jpeg" \
  -F "frame_2=@$OUT/frame_2.jpg;type=image/jpeg" -F "frame_3=@$OUT/frame_3.jpg;type=image/jpeg" \
  -F "frame_4=@$OUT/frame_4.jpg;type=image/jpeg" -F "meta=<$OUT/meta.json" -D "$OUT/headers.txt" \
  | "$PY" -m json.tool
grep -i "x-latency-ms" "$OUT/headers.txt"
echo "== replay same nonce (expect 409)"
curl -sS -X POST "$EDGE/v1/attempt/$ATT/frames" \
  -F "frame_0=@$OUT/frame_0.jpg;type=image/jpeg" -F "frame_1=@$OUT/frame_1.jpg;type=image/jpeg" \
  -F "frame_2=@$OUT/frame_2.jpg;type=image/jpeg" -F "frame_3=@$OUT/frame_3.jpg;type=image/jpeg" \
  -F "frame_4=@$OUT/frame_4.jpg;type=image/jpeg" -F "meta=<$OUT/meta.json" -w '  HTTP %{http_code}\n'
