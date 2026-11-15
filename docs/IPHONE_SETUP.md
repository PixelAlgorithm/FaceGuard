# iPhone 16 Pro Max depth setup — free route (own app, front TrueDepth camera)

The iPhone 16 Pro Max **is available**. Record3D is **NOT used**: it is paid, and the edge can't consume
its stream. Instead Claude writes a tiny iOS app, **DepthProbe**, that reads the front TrueDepth camera with
Apple's free public APIs and sends 1–3 depth frames (+1 JPEG) per attempt to the edge service over the
local network, where Python runs the depth checks. `depth-iphone` owns it (H4 go/no-go).

Endpoints and payloads (`GET /v1/depth/pending`, `POST /v1/depth/frames`) are defined in
`docs/API.md` §3.17; this file only covers the phone side and the build.

## Status and the route actually used today (2026-11-14)

- **Installed build: DepthProbe v0.3.0**, an unsigned IPA (`depth/ios/dist/DepthProbe-0.3.0.ipa`) that the
  operator installed with Sideloadly ("Install" below). A newer **v0.3.1** IPA (`dist/DepthProbe-0.3.1.ipa`,
  built 2026-11-14 19:30 IST; `MARKETING_VERSION` 0.3.1 in `depth/ios/project.yml`) exists; it is not recorded
  as installed, so check the app's screen header. `dist/DepthProbe.ipa` and `dist/DepthProbe-0.2.0.ipa` are
  older builds.
- **"Connects", not "is connected"**: the app is connected only while it runs and polls. `GET /v1/health`
  `depth_probe` is `connected` (polled in the last 30 s), `rejected_token` (polling with a wrong
  `X-Depth-Token`) or `unavailable`; the live edge reported `unavailable` at ~22:00 IST.
- **Depth is still disabled** (`liveness.depth.enabled: false` in `config/thresholds.yaml`; the setting
  belongs to `policy-engine`). Depth affects decisions only when it is `true`, and it is switched on only
  after the H4 calibration below reports GO. Until then the edge queues no depth captures
  (`/v1/depth/pending` long-polls to 204) and answers `POST /v1/depth/frames` with `409 INVALID_STATE`
  ("depth disabled").
- **The H4 go/no-go has not been run yet** (procedure below); `depth/calibration/` holds only `.gitkeep`.
- Continuity Camera gives RGB only, and it can't run while DepthProbe runs.

### Network (the topology that worked today)

- The iPhone shares its **Personal Hotspot over a USB-C cable**. The Mac gets `172.20.10.x` on the
  "iPhone USB" interface; the iPhone itself is `172.20.10.1`.
- The edge has a **LAN listener on `0.0.0.0:8001`** (`EDGE_LAN_PORT`). It serves only `/v1/depth/*` and
  requires the `X-Depth-Token` header. The main API on `127.0.0.1:8000` is not reachable from the phone.
  Each pending job carries a single-use `depth_nonce` that the upload must echo (else 403). On the Mac,
  `GET http://127.0.0.1:8000/v1/health` shows `detail.lan_listener` (`listening 0.0.0.0:8001`) and
  `depth_probe` (`connected` = the app polled in the last 30 s; `rejected_token` = it polls with a wrong token). Allow incoming connections for the
  edge's Python if the macOS firewall asks.
- Venue Wi-Fi works only if it allows device-to-device traffic (no client isolation).

### Install (unsigned IPA + Sideloadly)

1. Build (Claude): `depth/ios/build_install.sh --ipa` writes the **unsigned**
   `depth/ios/dist/DepthProbe-<MARKETING_VERSION>.ipa`. The script sets
   `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` itself (no `sudo xcode-select -s`) and runs
   `xcodegen` to regenerate the project from `depth/ios/project.yml`. For every new IPA, bump
   `MARKETING_VERSION` there; `ProbeModel.appVersion` reads `CFBundleShortVersionString` from the bundle, so
   the screen header and `app_version` follow it.
2. Install (operator): Sideloadly with the newest IPA (`depth/ios/dist/DepthProbe-0.3.1.ipa`; 0.3.0 is the
   one installed so far) and the same Apple ID as
   before. Sideloadly adds the team suffix, so the bundle id is `com.prajwalm.depthprobe.JM744Y953Z`; a
   different Apple ID would install a second "DepthProbe".
3. On the iPhone: trust the developer under Settings > General > VPN & Device Management. Developer Mode
   must be on (Settings > Privacy & Security > Developer Mode).
4. First launch: allow Camera and Local Network. The screen header reads `DepthProbe <version>` (0.3.0 or
   0.3.1).

The Xcode route with the free Personal Team `M72UUB7JCQ` currently fails at install with "The provisioning
profile is banned" (`0xe8008024`); see the reference section at the end.

### App settings and behaviour (v0.3.0)

| Field | Value |
|---|---|
| Edge URL | `http://<Mac IP>:8001` (`EDGE_LAN_PORT`, not 8000); typing just the IP works (the app adds `http://` and `:8001`). On the USB hotspot the Mac is `172.20.10.x`; a fresh install defaults to `http://172.20.10.3:8001` (the Mac's address on 14 Nov). Set it with the `pair.sh` QR or Find Mac. |
| Token | `DEPTH_DEVICE_TOKEN` from the project `.env`, sent as `X-Depth-Token`. Set it with the `pair.sh` QR or Paste; never paste it into chat or logs. |

- It **connects by itself** whenever it is on screen (unless Stop was tapped) and keeps the screen awake.
  iOS stops the camera when the app goes to the background; reopening the app reconnects.
- A **status card** at the top shows **Edge** and **Camera**, each with a cause and a fix; the Edge row
  also shows the raw system error.
- It polls with `wait_s=0` first, so a wrong IP, port or token shows within seconds, then long-polls with
  `wait_s=20`.
- **Find Mac** scans the phone's own subnets, hotspot first, on the configured port and on 8001. It scans
  at most a /24, and its probes carry no token (the edge's 401 reply identifies it). It also runs
  automatically after two network failures (at most every 30 s).
- **Token**: a **Paste** button and a **Show** toggle. The token is trimmed of quotes and spaces the same
  way the edge reads `.env`. Paste also accepts a pairing link or an `http://` edge URL.
- A **pairing link**, `depthprobe://config?url=...&token=...`, sets the URL and the token. A
  `-pairingLink '<link>'` launch argument does the same (it puts the token on a command line; prefer the
  QR).
- Keep the defaults (Send 1 RGB JPEG on, Depth width 320). **Test capture (local only)** checks depth
  without sending anything.

### Pairing (`depth/ios/pair.sh`)

1. On the Mac, run `depth/ios/pair.sh`. It shows a QR code: scan it with the iPhone **Camera** app, tap
   "Open in DepthProbe", then tap **Open**.
2. It also copies the link to the clipboard; with Universal Clipboard, tap **Paste** in the app.
3. It never prints the token. It also checks that the LAN listener answers (401 without a token is
   expected), prints the edge health and, if the macOS firewall is on, whether it allows the edge's
   Python. Press Enter after pairing to delete the QR and clear the clipboard.

Options: `--no-qr` (clipboard only), `--no-clipboard`, `--no-open` (print the QR PNG path instead of
opening Preview), `--no-wait` (the QR is deleted after 2 minutes; the clipboard is not cleared).
Variables: `MAC_IP=172.20.10.3` forces the address (default: the default-route interface, else en0/en1;
on the hotspot it must print `172.20.10.x`); `ENV_FILE` (default: the project `.env`).

### Troubleshooting

| Symptom | Fix |
|---|---|
| Token missing or rejected (HTTP 401) | Use the `pair.sh` QR. The edge reads `.env` only at startup, so a token changed in `.env` after that works only once the edge restarts. |
| "... refused the connection" | Wrong port, or the edge is down. Use port 8001. |
| "No reply from ... (timed out)" | Wrong IP, a different network, or client isolation. Use the hotspot. |
| "Local Network access is OFF" | Settings > Privacy & Security > Local Network > DepthProbe. |
| "Camera in use by another app" | Close Camera or FaceTime. Continuity Camera cannot run at the same time as DepthProbe. |
| "Phone too hot" | Let it cool. |
| Edge green ("Connected to ... - token OK"), but no attempts arrive | Expected while `liveness.depth.enabled` is false: the edge queues no captures. |

## H4 calibration (go/no-go): `python -m depth.calibrate`

`depth/calibrate.py` is a stand-alone stand-in for the edge's LAN listener. It uses the same port,
token check, `depth_nonce` echo and multipart contract, and it logs **numbers and labels only** (no
depth maps, images or tokens) to `depth/calibration/depth_calibration.csv`. Run it from the project root
with the edge venv:

1. Start the calibration server for live faces:
   `edge/.venv/bin/python -m depth.calibrate serve --label live --subject s01`
   While the edge holds 8001, the server falls back to **:8002**. Point the app at it: edit the Edge URL
   to `http://<Mac IP>:8002` (same token) for the session, and set it back to `:8001` afterwards. Don't
   use Find Mac for this: it recognises only the edge. If `serve` is down for two polls (e.g. a restart),
   the app's automatic search can move the URL back to the edge on `:8001`, so check the port before each
   batch.
2. The app connects by itself (Edge: "Connected to <Mac IP>:8002 - token OK"). In the console: Enter = one
   capture, `n 10` = ten captures, `c` = one challenge capture (open the mouth or smile when prompted, for
   M1), `sum` = summary, `q` = quit.
3. Capture **≥ 10 live PASSIVE** attempts (consenting teammate, 25–50 cm, indoors, phone on power).
4. Switch the label with `l print` and capture **≥ 10 printed-photo PASSIVE** attempts (A4 colour
   print of an enrolled teammate, held flat and then slightly bent).
5. `edge/.venv/bin/python -m depth.calibrate summary` prints per-label statistics and the verdict
   line. **GO** only if D1 FAILs every print and PASSes every live face, with at least 10 of each
   (`--min-n 10`). The verdict states the rule-of-3 bound, e.g. 0/10 errors → true error rate < 30 %
   at 95 %. That is a go/no-go for the demo, **not** an accuracy claim.
6. On GO: ask `policy-engine` to set `liveness.depth.enabled: true` (and to record the calibration CSV
   path next to any threshold change), restart the edge, and point the app back at `:8001`. Then run one
   real kiosk attempt: the app's **Last upload** must say OK and the decision's `scores.depth` must not be
   null (late depth counts as NOT_AVAILABLE). On NO-GO: depth goes to a roadmap slide, and the core
   liveness stack stands on its own.

`edge/.venv/bin/python -m depth.calibrate synth` is a pipeline smoke test without the phone. It writes
to a separate `depth_calibration_synthetic.csv` and is never used for the verdict.

---

## Original free-team route (kept for reference; fails on this device today)

`depth/ios/build_install.sh` without arguments runs this route: a Debug build signed with the free Personal
Team `M72UUB7JCQ`, installed and launched with `devicectl`. The install currently fails with "The
provisioning profile is banned" (`0xe8008024`), so use the Sideloadly route above.

## What the operator must do (one-time)

1. **Xcode — done.** Xcode is installed at `/Applications/Xcode.app` together with the iOS Simulator
   runtime (checked 14 Nov: `xcodebuild -version` → Xcode 27.2; `xcrun simctl list runtimes` → iOS 27.2).
   Open it once, accept the licence and let it install components if it asks. `xcode-select` still points at the
   Command Line Tools (`/Library/Developer/CommandLineTools`); **no `sudo xcode-select -s` is needed** —
   every Xcode command below is run with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`.
2. Xcode → Settings → Accounts → add your **Apple ID** (free "Personal Team" is enough; no paid program).
3. On the iPhone: Settings → Privacy & Security → **Developer Mode → On** (phone restarts).
4. Connect the iPhone to the Mac by USB-C once, tap **Trust This Computer**.
5. After the first install: iPhone Settings → General → **VPN & Device Management** → trust your developer
   certificate. (Free-team signed apps expire after ~7 days — fine for today.)
6. Put the Mac and iPhone on the **same Wi-Fi** (or connect the Mac to the iPhone's hotspot — the most
   reliable option at a venue). Allow "Local Network" access when the app asks.

## What Claude builds (`depth/ios/DepthProbe/`, SwiftUI)

- Capture: `AVCaptureDevice` `.builtInTrueDepthCamera` (front) + `AVCaptureDepthDataOutput`
  (`isFilteringEnabled = false`) + `AVCaptureVideoDataOutput`, synchronised with
  `AVCaptureDataOutputSynchronizer`. Reference: Apple sample "Streaming depth data from the TrueDepth
  camera" (TrueDepthStreamer): https://developer.apple.com/documentation/avfoundation/streaming-depth-data-from-the-truedepth-camera
- Face box + landmarks: Vision (`VNDetectFaceLandmarksRequest`) on the synchronised video frame, per frame
  for CHALLENGE. No ARKit.
- Keep the app DUMB (least Swift): it only captures and sends. The Python edge service runs the
  checks D0–D4 / M1–M3 (`depth/checks.py`, reusing the numpy code in the `liveness-kiosk` skill
  reference R9; thresholds from `config/thresholds.yaml` `depth:`).
- Network (push, no laptop-side bridge): the kiosk calls `POST /v1/session/start`; the app long-polls
  `GET /v1/depth/pending` (returns `attempt_id` + capture window), captures 1–3 synchronised depth frames
  (~320×240 float16, ~150 KB each) + 1 JPEG + camera intrinsics + depth type (disparity/depth) **during the
  colour-flash capture window**, and pushes them via `POST /v1/depth/frames` (multipart). The edge waits at
  most `latency_budget_ms.depth_max_wait` after the RGB frames; late depth is ignored (`NOT_AVAILABLE`, no
  effect on the decision). Never stream video.
- In the app, set the edge URL to `http://<mac-ip>:<EDGE_LAN_PORT>` (Mac's Wi-Fi / hotspot IP; `EDGE_LAN_PORT`
  is 8001 in `.env.example`) and the token `X-Depth-Token` = `DEPTH_DEVICE_TOKEN` from `.env` (easiest: the
  `pair.sh` QR, above). That LAN listener serves only `GET /v1/depth/pending` + `POST /v1/depth/frames`;
  the main edge API stays on `127.0.0.1:8000`. Depth is used only when `liveness.depth.enabled: true` in
  `config/thresholds.yaml` (owned by `policy-engine`).
- Also capture 1 depth frame during the mouth challenge so M1 (mouth deforms, forehead rigid) works.
- Mount the phone at face height, 25–50 cm from the user, indoors (sunlight washes out IR). Keep it on power.
- Log which depth units arrive (TrueDepth = disparity-based), `accuracy` (absolute/relative; D4 needs
  absolute) and the raw check values. `depth/calibrate.py` writes them to
  `depth/calibration/depth_calibration.csv` (see the H4 section above).

Build from the command line (Claude runs it; target the phone **by UDID**, not by name):
```bash
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer   # xcode-select points at the CLT; no sudo needed
xcrun xctrace list devices          # find the iPhone 16 Pro Max UDID (or: xcrun devicectl list devices)
# 14 Nov: a connected "Prajwal's iPhone" (iOS 27.0.1) showed UDID 00008140-00027D6034D8801C — confirm it is the 16 Pro Max
xcodebuild -project depth/ios/DepthProbe.xcodeproj -scheme DepthProbe \
  -destination 'id=<UDID>' -allowProvisioningUpdates DEVELOPMENT_TEAM=<TEAM_ID> build
```
(First signing usually needs one click in Xcode: target → Signing & Capabilities → Team = Personal Team;
the bundle id in `depth/ios/project.yml` is `com.prajwalm.depthprobe`.)

**iOS Simulator (installed): compile and UI checks only.** The Simulator has no TrueDepth camera, so it
cannot produce depth frames and cannot be used for the H4 go/no-go or for any depth number. It is useful
for a quick compile check without the phone, e.g.
`DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project depth/ios/DepthProbe.xcodeproj -scheme DepthProbe -destination 'generic/platform=iOS Simulator' build`,
and for checking the settings screen / edge-URL handling (the app should report the camera as unavailable).

## Go / no-go at H4

GO if: app runs on the **physical** iPhone 16 Pro Max, a result reaches the edge service for a real
attempt, AND D1 rejects a printed photo while passing a live face (procedure and the 10 + 10 rule:
"H4 calibration" above). Today only the first condition is shown: the app runs on the phone and reaches
the edge's LAN listener. The second needs depth enabled (the edge queues no capture while
`liveness.depth.enabled` is false), so it is checked in step 6. The third is the H4 calibration, which has
not been run yet. NO-GO → drop depth to a roadmap slide; core liveness (MiniFASNet + device + moiré +
colour flash + mouth challenge) stands on its own.

## Other options considered

| Option | Cost | Depth? | Verdict |
|---|---|---|---|
| Own app (above) | Free (needs Xcode + free Apple ID) | Yes, front TrueDepth | **Chosen** |
| Record3D USB / Wi-Fi streaming | Paid | Yes | Rejected (paid; the edge can't consume its stream) |
| Continuity Camera (iPhone as Mac webcam) | Free, built into macOS | **No — RGB only** | Use as a better webcam only (turn off Center Stage / Portrait / Studio Light), never while DepthProbe runs: the two can't run at the same time |
| iPhone Safari web page (getUserMedia) | Free | No depth exposed to the web | Not viable for depth |
| Rear LiDAR apps | Varies | Rear-facing, low-res, ML-filled | Wrong sensor for a kiosk face |
