> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# iPhone 16 Pro Max as kiosk camera + depth sensor for PAD (hackathon research)

Date: 2026-11-14. Context: `basic_idea.txt` (browser kiosk + FastAPI + MiniFASNet + colour flash + Rekognition; "silicone mask = roadmap: depth/IR camera").

Legend: **[src]** = taken from a fetched primary source (listed at the end). **[est]** = my estimate or general knowledge, not verified today. Test anything marked [est] in the first hour.

---

## 0. Verdict (TL;DR)

- **Adding depth is a good idea. Use the front TrueDepth camera, not the rear LiDAR.**
  - TrueDepth faces the user when the phone's screen faces the user, which is the normal kiosk pose. Apple tunes it for faces at about 10-20 in (25-50 cm) [src: Apple Face ID support].
  - With ARKit face tracking it also gives you a face mesh and blendshapes.
  - Rear LiDAR only works if the phone is mounted with its back toward the user. Its dense depth is an ML fusion of *sparse* LiDAR returns with the RGB image [src: WWDC22 110429], and it is built for room-scale measuring.
- **Depth makes print and screen attacks close to trivial.** Use planarity, nose relief and metric face size. CASIA-SURF (print/cut-print attacks, RealSense SR300 at 0.3-1.0 m): depth alone was the best single modality, ACER 5.0% vs RGB 11.3% [src: Zhang et al. CVPR 2019, Table 4].
- **Depth alone is NOT enough for 3D masks.** On WMCA (which includes rigid masks, silicone masks and mannequins), depth-only MC-CNN reached test APCER 11.77% / ACER 6.04%, while all channels reached ACER 0.3% [src: George et al. TIFS 2019, Table IX]. The same authors cite prior work showing "2D attacks are simple in depth; 3D masks simple in thermal" [src: WMCA §II, ref 43].
  - At basic level, catch rigid masks with *dynamics plus depth*: a non-rigid deformation challenge measured in depth, mask-edge/eye-hole depth steps, and shape mismatch against the enrolled depth template.
  - Silicone masks remain an honest limit.
- **Continuity Camera will not give you depth.** Apple's docs describe it as the iPhone's *rear wide camera* used as an external RGB camera with Center Stage, Portrait and Studio Light. Depth is not mentioned anywhere [src: Apple support 102546; "Supporting Continuity Camera in your macOS app"]. Treat it as RGB-only. To get depth you must run your own iOS app or a third-party app (Record3D).
- **Raw IR images from TrueDepth: no public API** [est]. `builtInTrueDepthCamera` is documented as "one Infrared and one YUV" camera, but it delivers only depth that is "synchronized and perspective corrected to the frame the YUV camera produces" [src]. No IR pixel output is documented. Apple Face ID's IR-image anti-spoofing is not available to apps.
- **Feasible in one day only if it is time-boxed to one person as an add-on.** The existing webcam pipeline stays the main path, and the depth signal plugs into the fusion as one more PASS/FAIL signal.

---

## 1. Hardware: TrueDepth (front) vs LiDAR (rear) on iPhone 16 Pro Max

The iPhone 16 Pro Max has both: "Face ID: Enabled by TrueDepth camera", 12MP f/1.9 front, and a LiDAR Scanner [src: Apple tech specs 121032]. USB-C is "USB 3 (up to 10Gb/s)" with a USB 3 cable [src].

| | **TrueDepth (front)** | **LiDAR (rear)** |
|---|---|---|
| Faces | Same side as the screen, so it faces the user in a kiosk | Back side. The user must face the phone's back (as in a Continuity Camera mount, where Apple says "rear cameras facing you" [src]) |
| Principle | IR dot projector + IR camera, "thousands of infrared dots" [src: Apple 102381]. Wikipedia cites WSJ for ">30,000 dots" [src: Wikipedia] | Time-of-flight. "Fusing sparse output from the LiDAR Scanner with the color image ... machine learning model that outputs a dense depth map" [src: WWDC22] |
| Designed range | Face ID "works best ... approximately 10-20 inches" (25-50 cm) [src: Apple 108411] | Room scanning / measurement [src: Apple LiDAR sample]. Works at 0.3-0.6 m but the native sparse grid is coarse at face scale [est] |
| Depth type | "Relative, disparity-based depth" [src: WWDC22]. Check `depthDataAccuracy` at runtime | "Absolute depth" (real-world scale) [src: WWDC22] |
| Streaming depth res | Not stated in fetched docs. Commonly 640x480 or 320x240 [est]. Query `activeFormat.supportedDepthDataFormats` and pick the largest float format, as Apple's TrueDepth sample does [src] | AVFoundation: "up to 320 by 240" streaming, 768x576 photo. ARKit `sceneDepth`: 256x192 [src: WWDC22] |
| Frame rate | ARKit: depth "at a different frame rate than the color camera", so `capturedDepthData` is often nil [src]. Commonly ~15 Hz depth vs 60 Hz colour [est] | Not stated in fetched docs. ARKit frames ~60 Hz [est] |
| Pixels across a face at 50 cm | ~100-200 px wide at 640x480 [est] | ~50-70 px at 256x192 or 320x240 (wide FoV ~70 deg gives ~0.7 m scene width) [est] |
| Extras | ARKit face mesh (~1220 vertices), blendshapes, eye transforms [est from ARKit docs] | Confidence map (ARKit), camera pose |

**Why TrueDepth wins for a kiosk:**
1. Orientation: the phone's screen and the user face the same way, and the phone screen can also run the colour flash.
2. Dense depth at face range, with a face-specific system around it (mesh and blendshapes).
3. LiDAR's dense map is ML-fused with RGB. A printed face *might* pick up some image-guided structure [est, untested], which is the opposite of what a PAD sensor needs. If you do use LiDAR, set `isFilteringEnabled = false`: "When filtering is disabled, the LiDAR Depth Camera excludes low confidence points" [src: WWDC22].

Use LiDAR only if the phone must also serve as a rear-facing Continuity-style webcam. Even then you cannot use Continuity Camera and your own capture app at the same time [est: camera is exclusive].

---

## 2. Continuity Camera

- Requirements: iPhone XR or later on iOS 16+, macOS Ventura+, same Apple Account with 2FA, Bluetooth and Wi-Fi on, phone "locked, and stable, with its rear cameras facing you" [src: 102546].
- Features: Center Stage, Portrait mode, Studio Light, Desk View, Reactions [src].
- On macOS it appears as an AVCaptureDevice (sample discovers it with `.externalUnknown`) [src: Supporting Continuity Camera]. It is plain video. **Depth, AVDepthData and IR are not mentioned anywhere.** Portrait mode is a system blur effect, not exported depth.
- Conclusion: Continuity Camera is a fine **high-quality RGB webcam** for the existing browser pipeline (the browser sees it as a normal camera). It adds **zero** depth. Turn Portrait, Center Stage and Studio Light OFF: they alter pixels and will skew MiniFASNet, moire and flash checks [est].

---

## 3. APIs

| API | Use | Notes |
|---|---|---|
| `AVCaptureDevice.default(.builtInTrueDepthCamera, for: .video, position: .front)` + `AVCaptureDepthDataOutput` + `AVCaptureDataOutputSynchronizer` | Synchronized RGB + depth stream | iOS 11.1+ [src]. Apple sample "Streaming depth data from the TrueDepth camera" selects the max-width `kCVPixelFormatType_DepthFloat16` format and sets `isFilteringEnabled = false` [src]. Warns about thermal state [src] |
| `.builtInLiDARDepthCamera` (position `.back`) | Rear RGB + absolute depth | iOS 15.4+ [src]. Sample uses `DepthFloat16` [src] |
| `AVDepthData` | Depth container | Depth in metres or disparity in 1/m, Float16/Float32 [src: AVDepthData; WWDC17]. Maps are **non-rectilinear** (lens-distorted to match YUV). "To use depth data for computer vision tasks, use ... `cameraCalibrationData` to rectify" [src]. Holes are NaN [src: WWDC17]. Has `depthDataAccuracy` (absolute/relative), `isDepthDataFiltered`, `depthDataQuality` [src] |
| `ARFaceTrackingConfiguration` | Face anchor pose, mesh, blendshapes (`jawOpen`, `mouthSmileLeft`, `eyeBlinkLeft`, ...), `ARFrame.capturedDepthData` | `capturedDepthData`: "available only in face-based experiences ... using the device's front TrueDepth camera", nil when no depth was captured with that colour frame [src] |
| `ARWorldTrackingConfiguration` + `.sceneDepth` | Rear LiDAR `ARDepthData` (`depthMap` in metres, `confidenceMap`) | iOS 14+ [src]. Float32 `fdep` example [src: depthMap] |
| Raw IR | n/a | No public API [est; nothing in the device-type docs exposes it] |

For face-scale geometry with good intrinsics, use plain AVFoundation TrueDepth with calibration data. For mesh, blendshapes and landmarks for free, use ARKit face tracking (depth arrives on a subset of frames, which is fine for 1 s capture windows).

**Will ARKit track a photo or mask?** Unknown, so test it. Apple extended face tracking to A12+ devices without TrueDepth (iOS 14), which suggests tracking is largely RGB-driven [est]. It will likely produce an anchor and even blendshapes on a printed photo or rigid mask. **Never treat "ARKit found a face" or "blendshape changed" as liveness by itself.** Always confirm against the depth map.

---

## 4. Getting data into our pipeline

### Option A (fastest, no Swift): Record3D -> laptop Python
- Record3D app (App Store) streams RGBD "from iOS devices with TrueDepth camera" and LiDAR over **USB** to a Python lib (`pip install record3d`, LGPL-2.1) [src: GitHub record3d].
- API: `Record3DStream.get_connected_devices()`, `session.connect(dev)`, `get_rgb_frame()`, `get_depth_frame()`, `get_confidence_frame()`, `get_intrinsic_mat()`, `get_device_type()` (0 = TrueDepth, 1 = LiDAR) [src: demo-main.py].
- **Wi-Fi** streaming to a browser needs the paid "Wi-Fi Streaming & RGBD Videos Extension Pack" [src: record3d.app; wifi demo repo]. Whether USB streaming is free today is unverified [est]. Check in the first 15 minutes, and budget a few dollars.
- Flow: a laptop "depth agent" (Python) reads frames, runs MediaPipe on the RGB, computes the depth features (section 5), and POSTs `{attempt_id, features}` to FastAPI. The browser kiosk is unchanged.
- Effort: 1-2 h to stream and visualise, plus 2-3 h for the algorithms [est].
- Weakness: a third-party app is in the trust chain (fine for a demo). TrueDepth mode needs the phone screen facing the user, so the RGB for MiniFASNet can still come from the browser webcam or from the Record3D RGB.

### Option B (cleanest): small SwiftUI + ARKit app, features computed on-device
- The app runs `ARFaceTrackingConfiguration`. On "start" (WebSocket message from FastAPI carrying `attempt_id` and the flash sequence), it captures about 1 s:
  - colour frames (JPEG, 3-5 frames)
  - depth frames (crop the face ROI and downsample to ~96x96 float16, about 18 KB each)
  - blendshapes timeline
  - intrinsics
- It then POSTs to FastAPI, or computes the scalar features on-device and sends only JSON plus 1-3 JPEGs.
- Optional: the phone screen performs the colour flash, which removes the laptop-screen-to-camera geometry problem.
- Needs:
  - a Mac + Xcode
  - an iPhone with Developer Mode on
  - a free Apple ID "Personal Team" signing. Free provisioning profiles expire after ~7 days [est, commonly reported], which is fine today.
  - a camera usage string in Info.plist
  - local-network permission if you use LAN WebSocket
- Effort [est]: with iOS/Swift experience 3-4 h to app + upload, plus 1-2 h features. Without iOS experience 6-8 h, which is too risky for a 10 h day. Use Option A, or have an LLM-assisted single-file ARKit app as a stretch goal.
- No Simulator support: the TrueDepth sample "will not build or run in the Xcode simulator" [src].

### Option C: run liveness fully on-device (Core ML) and send a verdict
Not recommended today: model conversion work, and harder to show reason codes. Computing scalar depth features on-device (Option B) already gets most of the benefit.

### Latency
On-device feature extraction takes milliseconds. Payloads are ~50-150 KB over LAN or USB, so <100 ms [est]. If the phone uploads straight to AWS Mumbai, send features + JPEG only. This fits the 1.3-1.9 s budget because the depth capture overlaps the existing ~1 s flash capture. Do not stream raw depth video to EC2.

---

## 5. Minimal depth algorithm spec (all thresholds [est]; tune on the day)

Preprocessing:
1. Get face landmarks: ARKit face anchor / mesh projection, or MediaPipe on the aligned RGB. Depth is aligned to RGB with matching FoV and aspect [src: device type docs], so scale the landmark coordinates by the resolution ratio.
2. Face ROI = convex hull of the landmarks, eroded by 10% to avoid hair and background.
3. Drop NaN and out-of-range values (keep 0.15-1.0 m). Take the median over 3-5 depth frames to cut noise.
4. Back-project to 3D using the intrinsics from `cameraCalibrationData` (rectify the lens distortion if you need mm accuracy) [src: AVDepthData]. Record3D gives intrinsics directly.

Checks (each produces PASS / UNSURE / FAIL for the existing two-threshold fusion):

| # | Check | Catches | Rule |
|---|---|---|---|
| D0 | Valid-depth ratio in ROI | Glossy screens, IR-absorbing, out of range | <40% valid: FAIL-ish (screen-like) or retake. >=60%: continue |
| D1 | **Planarity**: RANSAC plane fit, RMS of residuals | Flat print, phone, laptop | RMS < 3 mm: FAIL. > 6 mm: PASS (real faces ~8-15 mm). Between: UNSURE |
| D2 | **Bent print**: fit quadratic surface z = f(x, y) of degree 2, residual RMS | Curved or cylinder-bent paper | Residual < 2 mm: FAIL. > 4 mm: PASS (the nose bump isn't quadratic) |
| D3 | **Nose relief**: median depth of cheek patches minus nose-tip depth | Flat attacks, crude masks | >= 15 mm: PASS (adult nose protrudes ~20-35 mm). < 8 mm: FAIL |
| D4 | **Metric face size**: inter-pupil distance in mm from depth + intrinsics | Small replay screens, scaled photos | Adult IPD ~54-74 mm. Outside 45-80 mm: FAIL. Needs absolute depth, so check `depthDataAccuracy`; if relative, skip or use LiDAR |
| D5 | **Depth-RGB liveness consistency**: D1 FAIL while MiniFASNet PASS (or the reverse) | Disagreement | Route to REQUEST VERIFICATION |
| M1 | **Non-rigid deformation challenge** (existing smile / open-mouth step-up) | Rigid 3D mask, eye-cut paper mask | Rigidly align the face point cloud (Kabsch/ICP on forehead + nose-bridge points) between neutral and challenge frames. Real: mouth/cheek residual > 4 mm while forehead residual < 2 mm. Rigid mask: both < 2 mm. Also require ARKit `jawOpen` > 0.4 or `mouthSmile*` > 0.5. If blendshapes say "moved" but depth says "rigid": FAIL (strong mask sign) |
| M2 | **Edge / eye-hole step**: depth gradient along the face outline and around the eye openings | Masks worn over a face | A sharp step > 10 mm on a closed ring around the eyes, or at the jaw/forehead boundary, inconsistent with skin: one mask warning sign |
| M3 | **Enrolled depth template**: at enrolment store the landmark-aligned, scale-normalised depth of the face ROI (e.g. 64x64). At auth compute RMS vs the template after alignment | Generic or other-person masks (Halloween, mannequin) | Same person ~2-4 mm, different shape > 6 mm. Beyond that: one warning sign. Won't stop a mask made from the enrolee's own scan (Bkav-style) |
| M4 | **Temporal micro-motion**: frame-to-frame non-rigid jitter of cheek depth at rest | Rigid masks / mannequins | Weak cue at TrueDepth noise levels. Log it only, don't gate on it |

Fusion (matches `basic_idea.txt`):
- D1/D2/D3/D4 FAIL = clear evidence, so DENY.
- One of M1-M3 flagged = REQUEST VERIFICATION. Two or more, or M1 "blendshape-yes / depth-rigid" = DENY.

Expected coverage:
- prints, screens, curved prints: D1-D4 (high confidence)
- eye-cut paper masks: D2/D3 + M1
- rigid plastic masks: M1 + M2 + M3 (moderate)
- silicone masks: they deform and have real relief, so expect misses. Thermal/SWIR is the literature answer [src: WMCA]

---

## 6. Precedent: Apple Face ID

- How it works: "projects and reads thousands of infrared dots to form a depth map of the face along with a 2D infrared image". The TrueDepth camera "randomizes the sequence of 2D images and depth map captures, and projects a device-specific random pattern" against digital and physical spoofs. "Neural networks for determining attention, matching, and antispoofing" [src: Apple Platform Security].
- "Face ID always requires depth information, which isn't found in print or 2D digital photographs." Apple claims less than 1 in 1,000,000 false match, higher for twins and siblings [src: Apple 102381].
- Bkav (Nov 2017): a ~$150 mask (3D-printed frame plus hand-made parts) reportedly unlocked an iPhone X. WIRED called it a "proof-of-concept"; it needed "a detailed measurement or digital scan of the iPhone owner's face" [src: Wikipedia, citing Wired/Verge]. Wired's own extensive mask attempts mostly failed [src: Wikipedia].
- Lessons for us:
  1. Depth plus IR plus learned anti-spoofing kills 2D attacks but **not** a well-made subject-specific 3D mask, even for Apple.
  2. Attention (eyes open, looking) is cheap and worth keeping.
  3. Randomised capture (our colour flash) is the same idea as Apple's randomised capture sequence.
  4. Present masks as "raised the bar, honest residual risk", not "solved".

---

## 7. Risks and demo logistics

- **Sunlight:** both sensors are active-IR. Strong sunlight's IR can wash out the dot pattern or the ToF signal [est]. Keep the kiosk indoors, away from windows, and add a "low depth validity: retake" reason code (D0).
- **Distance:** TrueDepth is at its best at 25-50 cm [src]. Mount the phone at face height with a stand and mark a floor or desk position. At more than 60 cm the face gets few depth pixels [est].
- **Glasses and hair:** glasses can cause holes, so the 40-60% D0 band avoids false DENY. Masks (medical) are out of scope.
- **Thermal throttling:** continuous depth plus ARKit heats the phone [src: Apple sample]. Run the session only during an attempt. Plug in power (USB-C).
- **Two-camera sync:** if the browser webcam takes RGB while the phone takes depth, make sure it is the same person. Simplest is one camera: use the phone's RGB from the same frames. Otherwise check that the face count and position are plausible in both within the same `attempt_id` time window.
- **Calibration and units:** TrueDepth may report *relative* accuracy (WWDC22 says disparity-based). D1-D3 still work in relative units if you normalise by face width; D4 needs absolute depth. Log `depthDataAccuracy` on the day.
- **Injection:** a phone app sending features is itself a trust boundary. For the demo, pin the LAN IP and use a per-attempt nonce from the server.
- **Logistics:** Mac with Xcode installed beforehand (multi-GB download), Lightning/USB-C cable, Developer Mode enabled on the iPhone (needs a restart), Personal Team signing, phone stand, ring light.
- **Scope risk:** time-box depth to one person with a hard go/no-go at hour 4 (stream works + D1 detects a print). Otherwise drop it and keep it as the roadmap slide.

---

## 8. Build-time estimate (one person, [est])

| Task | Option A (Record3D) | Option B (Swift app) |
|---|---|---|
| Setup (install, signing, first frames on screen) | 0.5-1 h | 1-2 h (with iOS exp.) / 3-4 h (without) |
| Capture + transport tied to `attempt_id` | 1 h | 1.5-2 h |
| D0-D4 checks in Python/numpy (RANSAC, quadratic fit, landmarks to depth) | 2 h | 2 h (server side) or +1 h (on-device Swift) |
| M1 deformation + M3 template | 1.5-2 h | 1.5-2 h |
| Threshold tuning with print / phone / mask attempts | 1 h | 1 h |
| **Total** | **~6 h** | **~7-9 h (exp.) / 10+ h (no exp.)** |

Recommendation: **Option A with TrueDepth**, D0-D4 first (the high-value, near-certain win against print and screen), then M1 because it reuses the existing smile challenge. M2/M3 only if time remains.

---

## Sources (fetched 2026-11-14)
- Apple, `ARFrame.sceneDepth`: https://developer.apple.com/documentation/arkit/arframe/scenedepth
- Apple, `ARFrame.capturedDepthData`: https://developer.apple.com/documentation/arkit/arframe/captureddepthdata
- Apple, `ARDepthData.depthMap`: https://developer.apple.com/documentation/arkit/ardepthdata/depthmap
- Apple, `builtInLiDARDepthCamera`: https://developer.apple.com/documentation/avfoundation/avcapturedevice/devicetype-swift.struct/builtinlidardepthcamera
- Apple, `builtInTrueDepthCamera`: https://developer.apple.com/documentation/avfoundation/avcapturedevice/devicetype-swift.struct/builtintruedepthcamera
- Apple, `AVDepthData`: https://developer.apple.com/documentation/avfoundation/avdepthdata
- Apple sample, Capturing depth using the LiDAR camera: https://developer.apple.com/documentation/avfoundation/capturing-depth-using-the-lidar-camera
- Apple sample, Streaming depth data from the TrueDepth camera: https://developer.apple.com/documentation/avfoundation/streaming-depth-data-from-the-truedepth-camera
- Apple sample, Supporting Continuity Camera in your macOS app: https://developer.apple.com/documentation/avfoundation/supporting-continuity-camera-in-your-macos-app
- WWDC22 110429, Discover advancements in iOS camera capture (LiDAR 320x240 / 768x576, ARKit 256x192, absolute vs relative): https://developer.apple.com/videos/play/wwdc2022/110429/
- WWDC17 507, Capturing Depth in iPhone Photography (depth formats, NaN holes, relative/absolute; dual-camera numbers): https://developer.apple.com/videos/play/wwdc2017/507/
- Apple, Use Continuity Camera: https://support.apple.com/en-us/102546
- Apple, About Face ID advanced technology: https://support.apple.com/en-us/102381
- Apple, Face ID distance (10-20 in): https://support.apple.com/en-us/108411
- Apple Platform Security, Face ID: https://support.apple.com/guide/security/face-id-security-sec067eb0c9e/web
- Apple, iPhone 16 Pro Max tech specs: https://support.apple.com/en-us/121032
- Record3D lib: https://github.com/marek-simonik/record3d (+ demo-main.py). App: https://record3d.app/. Wi-Fi demo: https://github.com/marek-simonik/record3d-wifi-streaming-and-rgbd-mp4-3d-video-demo
- Zhang et al., "A Dataset and Benchmark for Large-scale Multi-modal Face Anti-spoofing" (CASIA-SURF), CVPR 2019, arXiv:1812.00408. Table 4: RGB ACER 11.3%, Depth 5.0%, IR 8.1%, all three 2.4%. Attacks are print / cut-print only; SR300 at 0.3-1.0 m.
- George et al., "Biometric Face PAD with Multi-Channel CNN" (WMCA), IEEE TIFS 2019, arXiv:1909.08848. Table IX: D-only test APCER 11.77% / ACER 6.04%; G+D+I 1.04%; G+D+I+T 0.3%. Attacks include rigid and silicone masks, mannequins, glasses.
- Erdogmus & Marcel, "Spoofing in 2D Face Recognition with 3D Masks and Anti-spoofing with Kinect" (3DMAD), BTAS 2013. 17 subjects, ThatsMyFace masks, Kinect 640x480. Block-LBP + LDA HTER 0.95% (colour) / 1.27% (depth). Small, single-mask-type dataset, so don't over-generalise. Dataset page: https://www.idiap.ch/en/scientific-research/data/3dmad
- Wikipedia, Face ID (Bkav 2017 mask, citing Wired and The Verge): https://en.wikipedia.org/wiki/Face_ID
