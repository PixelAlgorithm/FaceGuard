#!/usr/bin/env bash
# Build DepthProbe, install it on the iPhone and launch it. One shot, no loops.
#   depth/ios/build_install.sh --ipa           # WORKING ROUTE: unsigned Release IPA in dist/, install with Sideloadly
#   depth/ios/build_install.sh                 # free Personal Team (M72UUB7JCQ): builds, but FAILS at install on this
#                                              # iPhone ("The provisioning profile is banned", 0xe8008024)
#   DEVELOPMENT_TEAM=ABCDE12345 DEVICE_ID=<udid> BUNDLE_ID=com.you.depthprobe depth/ios/build_install.sh
# Needs (Xcode route, currently failing): Xcode (DEVELOPER_DIR override, no sudo), an Apple ID in Xcode >
# Settings > Accounts (free Personal Team), Developer Mode on the phone, phone connected by USB and trusted.
set -euo pipefail
cd "$(dirname "$0")"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
DEVICE_ID="${DEVICE_ID:-00008140-00027D6034D8801C}"
BUNDLE_ID="${BUNDLE_ID:-com.prajwalm.depthprobe}"
DD=/tmp/depthprobe_dd
VERSION="$(awk -F'"' '/^ *MARKETING_VERSION:/{print $2; exit}' project.yml)"
[[ "${VERSION}" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo "bad MARKETING_VERSION in project.yml: '${VERSION}'" >&2; exit 2; }

command -v xcodegen >/dev/null && xcodegen generate --quiet

# xcodebuild with a short summary; a failed build stops the script (no `| grep || true` masking).
run_build() {
  local log; log="$(mktemp /tmp/depthprobe_build.XXXXXX)"
  if ! xcodebuild "$@" >"${log}" 2>&1; then
    grep -E "error:" "${log}" | head -20 >&2 || true
    echo "BUILD FAILED (full log: ${log})" >&2
    exit 3
  fi
  grep -E "BUILD SUCCEEDED" "${log}" || true
  rm -f "${log}"
}

if [[ "${1:-}" == "--ipa" ]]; then
  APP=/tmp/depthprobe_ipa/Build/Products/Release-iphoneos/DepthProbe.app
  rm -rf "${APP}"  # never package a stale product from an earlier build
  run_build -project DepthProbe.xcodeproj -scheme DepthProbe -configuration Release \
    -destination 'generic/platform=iOS' -derivedDataPath /tmp/depthprobe_ipa CODE_SIGNING_ALLOWED=NO build
  [[ -d "${APP}" ]] || { echo "build failed (no ${APP})" >&2; exit 3; }
  STAGE="$(mktemp -d)"; mkdir -p "${STAGE}/Payload" dist; rm -f "dist/DepthProbe-${VERSION}.ipa"
  cp -R "${APP}" "${STAGE}/Payload/"
  (cd "${STAGE}" && zip -qry "${OLDPWD}/dist/DepthProbe-${VERSION}.ipa" Payload)
  rm -rf "${STAGE}"
  echo "unsigned IPA: $(pwd)/dist/DepthProbe-${VERSION}.ipa (sign + install with Sideloadly)"
  exit 0
fi

if [[ -z "${DEVELOPMENT_TEAM:-}" ]]; then
  DEVELOPMENT_TEAM="$(defaults export com.apple.dt.Xcode - 2>/dev/null | /usr/bin/python3 -I -c '
import plistlib, sys
try:
    data = plistlib.loads(sys.stdin.buffer.read())
except Exception:
    sys.exit(0)
teams = []
def walk(o):
    if isinstance(o, dict):
        if "teamID" in o:
            teams.append(o)
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)
walk(data)
teams.sort(key=lambda t: (not t.get("isFreeProvisioningTeam", False), str(t.get("teamName", ""))))
print(teams[0]["teamID"] if teams else "")
')"
fi
if [[ -z "${DEVELOPMENT_TEAM}" ]]; then
  echo "NO DEVELOPMENT TEAM: open Xcode > Settings > Accounts > + > Apple ID, sign in (free Personal Team)," >&2
  echo "then re-run this script (or pass DEVELOPMENT_TEAM=<10-char team id>)." >&2
  exit 2
fi
echo "team=${DEVELOPMENT_TEAM} device=${DEVICE_ID} bundle=${BUNDLE_ID} version=${VERSION}"

APP="${DD}/Build/Products/Debug-iphoneos/DepthProbe.app"
rm -rf "${APP}"  # never install a stale product from an earlier build
run_build -project DepthProbe.xcodeproj -scheme DepthProbe -configuration Debug \
  -destination "id=${DEVICE_ID}" -derivedDataPath "${DD}" -allowProvisioningUpdates \
  DEVELOPMENT_TEAM="${DEVELOPMENT_TEAM}" PRODUCT_BUNDLE_IDENTIFIER="${BUNDLE_ID}" build
[[ -d "${APP}" ]] || { echo "build failed (no ${APP})" >&2; exit 3; }
xcrun devicectl device install app --device "${DEVICE_ID}" "${APP}"

# A copy sideloaded with another Apple ID (e.g. Sideloadly: com.prajwalm.depthprobe.<TEAMID>) is a
# separate app with the same name: delete it on the phone so the operator opens the right one.
OTHERS="$(xcrun devicectl device info apps --device "${DEVICE_ID}" 2>/dev/null \
  | awk -v b="${BUNDLE_ID}" '$1=="DepthProbe" && $2!=b {print $2" (v"$3")"}')"
if [[ -n "${OTHERS}" ]]; then
  echo "NOTE: another DepthProbe is installed: ${OTHERS}. Delete it on the phone (long-press > Remove App);" >&2
  echo "      use the one that shows 'DepthProbe ${VERSION}' at the top." >&2
fi

# Launch fails while the phone is locked, and with an "untrusted developer" / "invalid code signature"
# error until the certificate is trusted: Settings > General > VPN & Device Management > Apple Development:
# <Apple ID> > Trust.
if ! xcrun devicectl device process launch --device "${DEVICE_ID}" --terminate-existing "${BUNDLE_ID}"; then
  echo "INSTALLED but not launched. Unlock the iPhone; if it still fails open Settings > General >" >&2
  echo "VPN & Device Management > 'Apple Development: <Apple ID>' > Trust, then open DepthProbe." >&2
  exit 4
fi
echo "DepthProbe ${VERSION} launched on ${DEVICE_ID}"
