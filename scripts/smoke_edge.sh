#!/usr/bin/env bash
# End-to-end curl smoke test against a running edge:
# health -> session/start -> probe -> frames (synthetic public-domain face, simulated flash) -> decision.
# Uses public kiosk routes only (no credential needed or sent).
# Target: EDGE_URL is required (e.g. EDGE_URL=http://127.0.0.1:8280 for a scratch edge). The live demo edge
# (port 8000) is refused unless SMOKE_LIVE=1; with SMOKE_LIVE=1 and no EDGE_URL it defaults to
# http://127.0.0.1:8000. Port 8001 (the edge's LAN depth listener) is never a smoke target.
# EDGE_URL is parsed strictly (http/https, host, numeric port; userinfo, path, query and fragment are dropped)
# and requests go to the normalised scheme://host:port base, so equivalent spellings such as :08000,
# :8000?x or :8000#f cannot slip past the guard. The smoke run creates real attempts (and a decision-log
# record) on the target edge.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIVE_EDGE="http://127.0.0.1:8000"
LIVE_PORT=8000
LAN_DEPTH_PORT=8001
if [[ -z "${EDGE_URL:-}" ]]; then
  if [[ "${SMOKE_LIVE:-0}" != "1" ]]; then
    echo "smoke_edge.sh: set EDGE_URL (scratch edge), or SMOKE_LIVE=1 to target the live edge $LIVE_EDGE" >&2
    exit 2
  fi
  EDGE_URL="$LIVE_EDGE"
fi
bad_url() {
  echo "smoke_edge.sh: bad EDGE_URL ($1); expected http(s)://host[:port]" >&2
  exit 2
}
if [[ "$EDGE_URL" =~ ^([hH][tT][tT][pP][sS]?)://(.*)$ ]]; then
  EDGE_SCHEME="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
  REST="${BASH_REMATCH[2]}"
else
  bad_url "scheme must be http or https"
fi
AUTHORITY="${REST%%[/?#]*}"   # drop path, query and fragment
AUTHORITY="${AUTHORITY##*@}"  # drop userinfo
if [[ "$AUTHORITY" =~ ^(\[[0-9A-Fa-f:.]+\])(:([^:]*))?$ ]]; then
  EDGE_HOST="${BASH_REMATCH[1]}"
  EDGE_PORT="${BASH_REMATCH[3]}"
  HAS_PORT="${BASH_REMATCH[2]}"
elif [[ "$AUTHORITY" =~ ^([A-Za-z0-9._-]+)(:([^:]*))?$ ]]; then
  EDGE_HOST="${BASH_REMATCH[1]}"
  EDGE_PORT="${BASH_REMATCH[3]}"
  HAS_PORT="${BASH_REMATCH[2]}"
else
  bad_url "cannot parse host"
fi
if [[ -z "$HAS_PORT" ]]; then
  if [[ "$EDGE_SCHEME" == "https" ]]; then EDGE_PORT=443; else EDGE_PORT=80; fi
fi
[[ "$EDGE_PORT" =~ ^[0-9]{1,5}$ ]] || bad_url "port must be numeric"
EDGE_PORT=$((10#$EDGE_PORT))
(( EDGE_PORT >= 1 && EDGE_PORT <= 65535 )) || bad_url "port out of range"
EDGE="$EDGE_SCHEME://$EDGE_HOST:$EDGE_PORT"
if (( EDGE_PORT == LAN_DEPTH_PORT )); then
  echo "smoke_edge.sh: refusing $EDGE (port $LAN_DEPTH_PORT is the edge's LAN depth listener, never a smoke target)" >&2
  exit 2
fi
if (( EDGE_PORT == LIVE_PORT )) && [[ "${SMOKE_LIVE:-0}" != "1" ]]; then
  echo "smoke_edge.sh: refusing $EDGE (port $LIVE_PORT is the live edge); set SMOKE_LIVE=1 to confirm" >&2
  exit 2
fi
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
