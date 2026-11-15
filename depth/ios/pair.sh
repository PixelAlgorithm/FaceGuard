#!/usr/bin/env bash
# Pair the DepthProbe iPhone app with this Mac's edge, with no typing on the phone.
#   depth/ios/pair.sh                       QR in Preview + setup link on the clipboard
#   depth/ios/pair.sh --no-qr               clipboard only (iPhone: DepthProbe > Paste)
#   MAC_IP=172.20.10.3 depth/ios/pair.sh    force the address (default: default-route interface, else en0/en1)
#   --no-open: write the QR PNG and print its path instead of opening Preview
# iPhone: Camera app > point at the QR > tap "Open in DepthProbe". The link is
#   depthprobe://config?url=http://<this Mac's LAN IP>:<EDGE_LAN_PORT>&token=<DEPTH_DEVICE_TOKEN>
# read the same way the edge reads .env (env vars win). The token is never printed; the QR image is
# deleted when you press Enter (or after 2 minutes) and the clipboard is cleared then.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT}/.env}"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
QR=1 CLIP=1 WAIT=1 OPEN=1
for a in "$@"; do
  case "$a" in
    --no-qr) QR=0 ;;
    --no-clipboard) CLIP=0 ;;
    --no-wait) WAIT=0 ;;
    --no-open) OPEN=0 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

# This Mac's LAN IP: the default-route interface (iPhone USB / hotspot = 172.20.10.x), else Wi-Fi.
IFACE="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
IP="${MAC_IP:-}"
if [[ -z "${IP}" && -n "${IFACE}" && "${IFACE}" != utun* ]]; then
  IP="$(ipconfig getifaddr "${IFACE}" 2>/dev/null || true)"
fi
for i in en0 en1; do
  if [[ -z "${IP}" ]]; then IP="$(ipconfig getifaddr "$i" 2>/dev/null || true)"; IFACE="$i"; fi
done
if [[ -z "${IP}" ]]; then
  echo "No LAN IP: connect the Mac to the iPhone hotspot (USB cable or Wi-Fi) or the phone's Wi-Fi." >&2
  exit 3
fi

TMP="$(mktemp -d /tmp/depthprobe_pair.XXXXXX)"
chmod 700 "${TMP}"
PNG="${TMP}/depthprobe_pair.png"
# Parse .env exactly like edge/config.py, build the link, hand it to pbcopy / the QR renderer via stdin.
# Only the port goes to stdout.
PORT="$(/usr/bin/python3 -I - "${ENV_FILE}" "${IP}" "${PNG}" "${QR}" "${CLIP}" "${HERE}/tools/qr.swift" <<'PY'
import os, re, subprocess, sys, urllib.parse

env_path, ip, png, want_qr, want_clip, qr_swift = sys.argv[1:7]

def parse_env_value(v):  # edge/config.py parse_env_value
    v = v.strip()
    if len(v) >= 2 and v[0] in "\"'":
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    if v.startswith("#"):
        return ""
    return re.sub(r"\s+#.*$", "", v).strip()

vals = {}
if os.path.isfile(env_path):
    with open(env_path, encoding="utf-8") as fh:
        for raw in fh.read().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            vals[key] = parse_env_value(value)

def get(name, default=""):  # edge: existing environment variables win over .env
    return os.environ[name] if name in os.environ else vals.get(name, default)

port = (get("EDGE_LAN_PORT", "8001") or "").strip()
if not port.isdigit() or int(port) == 0:
    sys.exit("EDGE_LAN_PORT is unset/0: the edge runs no LAN listener for the phone. "
             "Set EDGE_LAN_PORT=8001 in .env and restart the edge.")
token = get("DEPTH_DEVICE_TOKEN")
if not token:
    sys.exit("DEPTH_DEVICE_TOKEN is empty in " + env_path + ": the edge rejects every phone (HTTP 401). "
             "Set it and restart the edge.")
link = ("depthprobe://config?url=" + urllib.parse.quote(f"http://{ip}:{port}", safe="")
        + "&token=" + urllib.parse.quote(token, safe=""))
if want_clip == "1":
    subprocess.run(["pbcopy"], input=link.encode(), check=True)
if want_qr == "1":
    subprocess.run(["xcrun", "swift", qr_swift, png], input=link.encode(), check=True)
print(port)
PY
)" || { rm -rf "${TMP}"; exit 4; }

echo "Mac LAN IP : ${IP} (${IFACE:-?})"
echo "Edge URL   : http://${IP}:${PORT}   token: DEPTH_DEVICE_TOKEN from ${ENV_FILE} (not shown)"
code="$(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://${IP}:${PORT}/v1/depth/pending?wait_s=0" || true)"
case "${code}" in
  401) echo "LAN listener: OK (answers 401 without a token, as expected)" ;;
  000) echo "LAN listener: NOT reachable at ${IP}:${PORT} - start the edge (EDGE_LAN_PORT=${PORT} in .env)" ;;
  *)   echo "LAN listener: unexpected HTTP ${code} at ${IP}:${PORT}" ;;
esac
health="$(curl -s -m 3 http://127.0.0.1:8000/v1/health || true)"
if [[ -n "${health}" ]]; then
  /usr/bin/python3 -I -c 'import json,sys; h=json.loads(sys.argv[1]); d=h.get("detail") or {}; print("Edge health: depth_probe=%s lan_listener=%s depth_enabled=%s" % (h.get("depth_probe"), d.get("lan_listener"), d.get("depth_enabled")))' "${health}" 2>/dev/null || true
else
  echo "Edge health: no answer on 127.0.0.1:8000 (edge not running?)"
fi
FW=/usr/libexec/ApplicationFirewall/socketfilterfw
EDGE_PY="$(/usr/bin/python3 -I -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${ROOT}/edge/.venv/bin/python" 2>/dev/null || true)"
if [[ -n "${EDGE_PY}" && -x "${FW}" ]] && "${FW}" --getglobalstate 2>/dev/null | grep -q enabled; then
  if "${FW}" --getappblocked "${EDGE_PY}" 2>/dev/null | grep -q "is permitted"; then
    echo "Firewall   : on, edge python allowed"
  else
    echo "Firewall   : on and the edge python may be BLOCKED - System Settings > Network > Firewall > Options > allow ${EDGE_PY}"
  fi
fi

clear_clip() { if pbpaste 2>/dev/null | grep -q '^depthprobe://'; then printf '' | pbcopy; fi; }
[[ "${CLIP}" == 1 ]] && echo "Clipboard  : setup link copied - on the iPhone open DepthProbe > Paste (Universal Clipboard)"
if [[ "${QR}" == 1 && "${OPEN}" == 1 ]]; then
  open "${PNG}"
  echo "QR         : opened in Preview - iPhone Camera app > point at it > tap 'Open in DepthProbe'"
elif [[ "${QR}" == 1 ]]; then
  echo "QR         : ${PNG} (deleted in 2 minutes)"
fi
if [[ "${WAIT}" == 1 && -t 0 ]]; then
  read -r -p "Press Enter after pairing to delete the QR and clear the clipboard... " _ || true
  rm -rf "${TMP}"
  clear_clip
  echo "Done. Close the Preview window."
else
  # the link carries the token: clear it from the clipboard too, not just the QR image
  ( sleep 120; rm -rf "${TMP}"; clear_clip ) >/dev/null 2>&1 &
  echo "Cleanup    : QR image and clipboard link are cleared in 2 minutes"
fi
