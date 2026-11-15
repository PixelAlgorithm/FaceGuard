---
name: liveness-kiosk
description: Implementation playbook for the HID entry-kiosk prototype. Use it whenever you implement, modify, debug or tune any part of the face liveness / presentation-attack detection pipeline (quality gate, MiniFASNet, phone/screen detector, moire FFT, colour-flash challenge, MediaPipe active challenge, injection / virtual-camera checks, optional iPhone TrueDepth depth via the DepthProbe app), face authentication (ArcFace/uniface local matcher, enrolment, template encryption, AWS Rekognition user vectors), the decision policy engine (ALLOW / REQUEST VERIFICATION / DENY), the SC1 campus-schedule evaluator, the SC2 offline mode (signed cache bundle, TOTP fallback, encrypted minimal log, sync queue), or end-to-end latency work on the 2 s budget.
---

> **Where this conflicts with `docs/DECISION_POLICY.md`, `config/thresholds.yaml` or `docs/API.md` v1.1,
> those win.** Numbers quoted here are copied from the YAML for convenience; always read the YAML key
> named next to them. Reason codes are the **closed list** in `DECISION_POLICY.md` §6 (= `API.md` §2) —
> never invent a code. Code in `reference.md` may still use older names; map them to the canonical
> codes when you reuse it. Update this skill if you notice drift.
>
> Depth: our own free SwiftUI app **DepthProbe** (`depth/ios/`) pushes 1–3 TrueDepth depth frames per
> attempt to the edge (`GET /v1/depth/pending` long-poll, `POST /v1/depth/frames`). Record3D (paid) is
> not used; there is no laptop-side depth bridge. See `docs/IPHONE_SETUP.md`.
>
> UI label: the middle outcome is shown as **REQUEST VERIFICATION** (subtitle "step-up"); the API enum
> is `STEP_UP`.
>
> **As built (2026-11-14):** the system runs. Real code beats this playbook (`edge/`, `kiosk/`, `cloud/`, `depth/`;
> map in §12). Current switches: **colour flash ADVISORY** (`liveness.flash.enforce: false`), **depth disabled**
> until H4 (`liveness.depth.enabled: false`), **random challenge on** (`challenge.random_rate: 0.15` online / `0.30` offline), rate-limit
> lockout **5 s**. Capture = 5 frames over `liveness.flash.duration_ms` (700 ms, was 1000 ms) at up to 1280 px. **Test on your own port, never against the live
> `:8000` edge.**


# Liveness Kiosk Playbook

This is a working playbook for building the kiosk described in `CLAUDE.md`. That file is the source of
truth for the architecture. Read it first if you haven't.

**These files own the numbers and the contracts. Never hard-code a threshold in logic.**
- `config/thresholds.yaml`: every threshold (owner: `policy-engine`). Values quoted below are copies.
- `docs/DECISION_POLICY.md`: the fusion rules, decision matrix and reason codes.
- `docs/POLICY_TEST_CASES.md`: the test vectors the unit tests must cover (IDs Q, L, M, C, I, S, O, X, D, Y, P).
- `docs/SURPRISE_CHALLENGES.md`: SC1 (schedule) and SC2 (offline) requirements.
- `docs/API.md` v1.1: endpoint and payload contracts.
- `edge/policy/signals.py`: the typed signal models the policy engine consumes.

Long code is kept in `reference.md`, in this same folder. Section numbers below match it (R1, R2, ...).

---

## 0. Pipeline at a glance

```
Browser (kiosk/)                                Edge FastAPI (edge/)                     Cloud (cloud/, us-east-1)
 S0 camera open + injection probe ──┐
 S1 MediaPipe face lock + client QG │  POST /v1/session/start -> attempt_id, nonce, flash_sequence
 S2 colour-flash capture (~0.7 s)   │  POST /v1/attempt/{id}/frames  (multipart)
    + rVFC timestamps + ROI series ─┘          │        ▲ DepthProbe pushes depth frames during S2
                                     rate limit → server quality gate (detect, align, blur, luma, pose)
                                               │  (fail -> STEP_UP RECAPTURE)
                                     injection check (fail -> DENY)
                                     ┌─────────┴──────────┐   asyncio.gather, thread pool
                                     S4 liveness           S5 matching ─────────────► Rekognition
                                     (MiniFASNet x2,       (local ArcFace always;    SearchUsersByImage
                                      device det, moire,    cloud when online,        (online only,
                                      flash NCC, depth?)    time-boxed)               time-boxed)
                                     └─────────┬──────────┘
                                     S6 policy.evaluate(att, ctx) -> Decision
                                        (bio fusion → random challenge → evaluate_schedule on the
                                         signed bundle → offline rules)
                                     S7 log (encrypted minimal record) + sync queue + response
 S8 UI shows decision + reason; on STEP_UP ("REQUEST VERIFICATION") -> next_action
    (RECAPTURE / CHALLENGE / SECOND_FACTOR); then POST /v1/attempt/{id}/rendered beacon
```

### Stage contracts (the "exact contract")
Every stage is a pure-ish function. It takes typed input and returns a typed result that has
`ok | fail | unsure`, `scores`, candidate `reason_codes`, `latency_ms`. A stage does **not** decide
ALLOW/DENY. Only S6 decides. Signal models live in `edge/policy/signals.py` (policy-engine) and wire
models in `edge/schemas.py` (edge-ml); keep the wire format in sync with `docs/API.md` v1.1.

| Stage | Input | Output (fields that must exist) |
|---|---|---|
| S0 injection (client) | MediaStream | `device_label`, `device_id`, `virtual_cam: bool`, `frame_intervals_ms[]`, `jitter_ms`, `fps` |
| S1 face lock (client) | video frames | `face_box`, `yaw/pitch/roll`, `blendshapes{}`, `client_quality{}` (advisory only) |
| S2 capture (client) | flash sequence from server | `frames[]` (5 JPEG over `liveness.flash.duration_ms` 700 ms, q≈0.9, up to `CaptureSpec.max_width_px` 1280 px wide (640 px gave ~50 px IOD → every frame `QUALITY_POSE`), **unmirrored**), `frame_ts_ms[]` (rVFC `mediaTime`/`expectedDisplayTime`), `roi_series[]` (t, r,g,b at ~30 fps), `flash_events[]` (t, colour actually painted), `nonce`, `flash_enabled` |
| S3 quality | frames | `QualityResult{ok, best_frame_idx, face_box, kps5, blur, luma, overexposed_fraction, face_px, iod_px, yaw, pitch, roll, n_faces, codes[]}` |
| S4 liveness | frames + QualityResult + client series | `LivenessSignals{pad_frames[], device{label,conf,face_containment}, moire{score}, flash{r,lag_frames,lag_std,amplitude,status}, depth?{D0..D4,M1..M3}, injection{...}, mask{...}}` |
| S5 match | aligned 112×112 crop(s) | `MatchResult{source: local|rekognition|both, top1_id, top1, top2, margin, rekognition?, status: PASS|UNSURE|FAIL, codes[]}` |
| S6 policy | attempt + ctx (thresholds, connectivity, bundle store, clock, RNG) | `Decision{attempt_id, decision, reason_codes[], resolved_codes[], next_action, scores{}, latency_ms{}, mode, cache_state, policy_version, bundle_version}` (`DECISION_POLICY.md` §10) |

Rules that apply everywhere:
- **The server recomputes everything security-relevant.** Client scores are hints for the UI. The only client values you accept are the raw time series, and you cross-check them (see §4).
- Every stage measures its own `latency_ms` (`time.perf_counter`), and the response returns all of them.
- If a stage raises an exception or gets invalid input, the attempt is `DENY` + `SYSTEM_ERROR` (P1). A missing optional signal (e.g. depth) is `NOT_AVAILABLE`, never a pass. **Fail-secure.**

---

## 1. Face detection, alignment and quality gate (S3)

- Detector: SCRFD or RetinaFace via `uniface` (`pip install "uniface[cpu]"`, MIT code). Check the uniface README for the current class names and model licences. The detector gives a box, a score and 5 keypoints (eyes, nose, mouth corners).
- Alignment: similarity transform from the 5 keypoints to the standard ArcFace 112×112 template (R2). Use the aligned crop **for matching only**. MiniFASNet uses its own *unaligned* scaled crop (§2).
- Choose the best frame (sharpest frame that passes) for matching, and use all passing frames for liveness voting.

Per-frame checks (`config/thresholds.yaml` `quality:`; semantics `DECISION_POLICY.md` §3.1). A frame
failing any check is dropped:

| Check | How | YAML key = value | Code |
|---|---|---|---|
| Exactly one face | 2nd face counts if its area ≥ `secondary_face_min_rel_size` × main face | 0.5 | `MULTIPLE_FACES` (on any frame → attempt fails) |
| Face size | face box width / inter-ocular distance (IOD) from kps | `min_face_width_px` 112, `min_interocular_px` 60 | `QUALITY_POSE` |
| Pose | yaw/pitch/roll from the MediaPipe matrix or 5-kps proxies | `max_abs_yaw_deg` 25, `max_abs_pitch_deg` 20, `max_abs_roll_deg` 20 | `QUALITY_POSE` |
| No face / truncated | no detection, or face box cut off by the frame edge | — (detector default score) | `QUALITY_POSE` (frame dropped) |
| Blur | `cv2.Laplacian(gray112, cv2.CV_64F).var()` on the 112×112 grey crop | `min_laplacian_var` 80 [cal] | `QUALITY_BLUR` |
| Brightness | mean luma Y in the face ROI | `min_luma_mean` 60, `max_luma_mean` 210 [cal] | `QUALITY_LOW_LIGHT` |
| Backlight / clipping | fraction of ROI pixels with Y ≥ 250 | `max_overexposed_fraction` 0.15 [cal] | `QUALITY_LOW_LIGHT` |
| Depth validity (depth on) | D0 valid-depth ratio | `liveness.depth.d0_valid_fail_below` 0.40 | `QUALITY_DEPTH_INVALID` |

Attempt level: usable frames ≥ `min_usable_frames` (3), else the attempt fails quality with the
deduplicated codes of the dropped frames. Quality fail → **STEP_UP / RECAPTURE** while
`recapture_count < max_recaptures` (2). A low-light retake is not an attack. When recaptures are
exhausted (D4): low/medium-risk zone → STEP_UP SECOND_FACTOR with `methods = [STAFF_OVERRIDE]` (manual
review by desk staff), success → ALLOW [`ACCESS_OK`, `FALLBACK_OK`] with the quality codes in
`resolved_codes`; high-risk zone → DENY CONTACT_DESK. Code: R1.

---

## 2. MiniFASNet passive anti-spoof (S4)

**Model files:** `MiniFASNetV2.onnx` and `MiniFASNetV1SE.onnx` come from the
`yakhyo/face-anti-spoofing` GitHub release (Apache-2.0). `scripts/fetch_models.sh` puts them in `models/`
(gitignored). SHA-256 pins and licences are in `edge/ml/MODELS.md`, and the edge re-verifies them at startup
(`edge/ml/registry.py`). **Self-test result on our weights: output index 1 = real, input raw 0-255 BGR**
(`GET /v1/health` → `self_test`).

**Preprocessing must exactly match upstream minivision `CropImage`:**
1. Start from the detector box `(x, y, w, h)`. Use the raw box, not an aligned crop.
2. scale = 2.7 for V2 and 4.0 for V1SE. Clamp it to `min((H-1)/h, (W-1)/w, scale)`.
3. New box = `w*scale × h*scale` around the box centre. **Shift it, don't shrink it**, so that it stays inside the image.
4. Crop, then `cv2.resize` to **80×80**. The image stays **BGR** (OpenCV order) and is laid out as CHW float32.
5. Normalisation: upstream PyTorch feeds **raw 0-255** values (its custom `ToTensor` does not divide). Some ONNX ports and model cards say `/255`. **Use whatever your export's reference `onnx_inference.py` uses, and confirm it with the check below.**

**Output:** 3 classes. Upstream `test.py` treats **index 1 as real** (0 and 2 are spoof types). One
HF card says `[live, print, replay]`, which conflicts with that. If the outputs are not already
probabilities (they don't sum to 1), apply softmax. Fuse the two models by **averaging their softmax
vectors**: `p = (softmax(v2) + softmax(v1se)) / 2`, then `P_live = p[real_class_index]`.

**Startup self-test (mandatory before trusting anything):** as built it uses the minivision sample
images in `models/fixtures/` plus the public-domain scikit-image astronaut (see `edge/ml/MODELS.md`). At startup,
or in `pytest -m models`, check that the mean `P_live` on the live fixtures is greater than on the
attack fixtures for the configured `liveness.pad.real_class_index` and normalisation. If the order is
inverted, the index or normalisation is wrong: fail loudly. (If you need an `input_scale` key, ask
`policy-engine` to add it to the YAML.)

**Multi-frame voting** (`liveness.pad`, `DECISION_POLICY.md` §3.3): PASS if ≥ `min_pass_frames` (3)
usable frames have `P_live` ≥ `pass_min` (0.80; offline 0.85) **and at most 1 frame** has `P_live` ≤
`fail_max` (R11); FAIL (`SPOOF_PASSIVE`, hard) if `P_live` ≤ `fail_max` (0.30) on a **strict majority** of
usable frames; otherwise UNSURE (`LIVENESS_UNSURE` → STEP_UP CHALLENGE). Fewer than 3 usable frames is a quality failure (§1), not a liveness result. Code: R3.

Known limits: RGB MiniFASNet generalises poorly to new cameras and lighting. A high-resolution phone
replay is the most likely way to fool it, which is why the device detector, moiré and flash checks
exist. It is weak on 3D masks. Calibrate on 50 or more captures from *the demo webcam*.

---

## 3. Device detector and moiré (S4)

**Device detector:** look for a COCO "cell phone", "laptop" or "tv" around the face.
- COCO class IDs: in the **80-class contiguous** index (YOLO/YOLOX style), `cell phone = 67`, `laptop = 63`, `tv = 62` (`liveness.device_detector.classes`). In the **original 91-id** category IDs (TF/EfficientDet label maps), they are 77 / 73 / 72. Match on the label *name* where you can.
- **As built: YOLOX-Tiny ONNX (Megvii, Apache-2.0), 416×416 letterbox, `edge/ml/device.py`.**
- **Licence:** Ultralytics YOLOv5/v8/11 code and weights are **AGPL-3.0**, so avoid them, or flag them on the licence slide if you use them anyway. Apache/MIT options:
  - **YOLOX-nano/tiny ONNX** (Megvii, Apache-2.0), 416×416, CPU at about 10-30 ms.
  - **MediaPipe Object Detector `efficientdet_lite0`** (Apache-2.0). It runs both in the browser (`@mediapipe/tasks-vision`) and in Python, and returns label names.
  - RT-DETR (Apache-2.0) is more accurate but heavier.
- Rule (`liveness.device_detector`): a device box with conf ≥ `fail_conf` (0.40) that contains ≥ `face_containment` (80 %) of the face box → `SPOOF_DEVICE_DETECTED` (hard spoof, DENY). **Any overlapping device box with conf ≥ `unsure_conf` (0.25) that is not a FAIL** (R10; e.g. conf ≥ 0.40 but containment < 80 %) → `LIVENESS_UNSURE`. A device elsewhere in the frame produces no code (log it in `scores` only), so someone holding a phone in their hand is not denied.
- Run it on 1-2 frames (the best frame plus one other). It does not need all of them.

**Moiré / FFT high-frequency check:** take the grey face crop at 128×128, apply a Hann window, then
compute the log-magnitude FFT. Measure (a) the ratio of energy in the outer annulus (r > 0.35·Nyquist)
to total energy, and (b) the peakiness of that band, max/median, and map them to a 0-1 score. Screens
produce sharp peaks, and prints often show halftone peaks. Thresholds (`liveness.moire`): score <
`unsure_score` (0.40) → pass; [0.40, 0.70) → `LIVENESS_UNSURE`; ≥ `fail_score` (0.70) → `SPOOF_MOIRE`
**only if corroborated** (PAD ≠ PASS or flash ≠ PASS), otherwise `LIVENESS_UNSURE`. Calibrate on live
faces versus a phone replay at the demo distance. JPEG compression and blur change the result, so
always compute it on the same JPEG quality. Code: R4.

---

## 4. Colour-flash reflection challenge (S2 + S4). This is our own code.

The reference repo (`watcharaponthod-code/ekyc`) has **no licence**. Read it for ideas only and do not
copy it. R5 is an original implementation.

**Protocol**
1. `POST /v1/session/start` returns `attempt_id`, the single-use `nonce` (TTL 10 s) and the flash sequence (exact shape: `docs/API.md` v1.1 §3.1). The sequence comes from `secrets` (never `random`): **exactly 3 distinct colours × ~233 ms** over `duration_ms` (700) (`colours_min` = `colours_max` = 3, R17), at most `max_changes_per_s` (3) changes per second (`edge/session.py`).
2. The browser paints a **full-screen overlay** with each colour, keeping a small transparent oval or the camera preview so the user stays framed. Brightness goes to max in kiosk mode. Log `performance.now()` at each paint (inside `requestAnimationFrame`) as `flash_events`, and log frame times through `video.requestVideoFrameCallback`.
3. During capture the browser records `roi_series` at camera rate: the mean R,G,B over a skin ROI (cheeks plus forehead from the landmarks, without the eyes and mouth). It also uploads 3-5 JPEG frames, ideally **one from the middle of each segment** (60-80 % into it, to avoid exposure lag at the transition) plus one baseline frame.
4. The server (a) recomputes the ROI means on the uploaded JPEGs, using the S3 kps for the ROI. **`r` = the edge-measured `r_frames` only** (C2): the client chroma series is untrusted, and it was noisy (genuine: r_client 0.33–0.98 vs r_frames 0.86–0.99, dev data). Any disagreement is logged in `scores` (there is no separate reason code — closed list). (b) It builds the expected chroma signal from the **server's own** flash sequence (and checks that `flash_events` agree with it). (c) It computes the correlation `r` of the observed and expected per-channel *chromaticity* (r/(r+g+b) and so on, which cancels most auto-exposure gain) over lags of `lag_min_frames`–`lag_max_frames`.
5. Outputs and zones (`liveness.flash`, `DECISION_POLICY.md` §3.3):
   - PASS: `r ≥ pass_min_r` (0.70; offline 0.75), lag within [`lag_min_frames` 0, `lag_max_frames` 8] frames (measured webcam pipeline delay 4–7 frames), lag std ≤ `lag_max_std_frames` (1.5). `lag_ms` from the client is converted with the measured fps.
   - FAIL → `SPOOF_FLASH_MISMATCH` (hard): amplitude ≥ `min_amplitude` **and** (`r < fail_max_r` 0.30, or lag outside the window — replay / re-render loop — or wrong colour order).
   - UNSURE → `LIVENESS_UNSURE`: 0.30 ≤ r < pass bar, **or** amplitude < `min_amplitude` (WEAK: bright ambient light or a dim screen). Low amplitude is never FAIL.
   - Ambient exception (online only, `ambient_exception_enabled`): WEAK flash + PAD PASS + mean `P_live` ≥ `strong_live` (0.90) **+ a clean device detector + moiré < `unsure_score`** (R12) → treated as PASS. Disabled offline.
   - **ADVISORY mode (as built, C3): `liveness.flash.enforce: false`.** The zone is still computed and reported as `ADVISORY_<zone>`, but it has no decision effect (it cannot FAIL or step up, and it cannot corroborate a moiré FAIL). This holds until the kiosk frame timing is re-validated. While advisory, video/screen-replay defence rests on PAD + device detector + moiré (+ depth when enabled). **Never claim the flash is enforced.**
   - Optional 3D cue: the nose and cheek response ratio compared with the forehead. A flat object responds uniformly.
6. **Non-flash accessibility path (D5):** `flash_enabled = false` → flash `NOT_AVAILABLE` → adds `LIVENESS_UNSURE` → a CHALLENGE step is always required (never an automatic ALLOW without the flash check).

**Caveats:** auto-exposure and white balance chase the flash. Try
`track.applyConstraints({advanced:[{exposureMode:'manual'},{whiteBalanceMode:'manual'}]})` and read
`getCapabilities()` first, because support varies. Strong ambient light or sunlight kills the
signal. Distance should be 30-60 cm. Phones held up to the camera emit their own light, so their
chroma barely follows the flash, which is good. **Photosensitivity:** at most 3 colour changes per
second, no saturated-red alternation, no strobing, softened transitions (a 30-50 ms CSS ease), a
visible "screen will change colour" notice, and the accessible non-flash path above (challenge +
fallback).

---

## 5. Active challenge: MediaPipe Face Landmarker, web (S1 / step-up)

- Use `@mediapipe/tasks-vision` `FaceLandmarker` in **VIDEO** mode (the web supports IMAGE and VIDEO only), driven by `requestAnimationFrame`, with `detectForVideo(video, performance.now())`. Options: `numFaces: 1`, `outputFaceBlendshapes: true`, `outputFacialTransformationMatrixes: true`, `delegate: "GPU"`, and the model `face_landmarker.task` served locally from `kiosk/public/models/` so it works offline. Code: R6.
- **Mirroring:** mirror only the *preview* (CSS `transform: scaleX(-1)`). Never mirror the frames you upload or run inference on. MediaPipe's Left and Right refer to the subject. If you mirror, the left/right turn and smile-side logic flips.
- Signals (`challenge:` in the YAML; baseline = mean blendshapes over the first `baseline_ms` (200) of neutral face):
  - deformation passes if the blendshape rises ≥ `deformation_rise_min` (0.45) above baseline **and** its absolute value exceeds the action's bar: smile = mean(`mouthSmileLeft`, `mouthSmileRight`) ≥ `smile_abs_min` (0.50); open mouth = `jawOpen` ≥ `jaw_open_abs_min` (0.40); cheek puff = `cheekPuff` ≥ `cheek_puff_abs_min` (0.40). `cheekPuff` scores weakly on many faces — test it on teammates and, if unreliable, ask `policy-engine` to drop it from `deformation_actions`.
  - blink: `eyeBlinkLeft/Right` ≥ `blink_close_min` (0.5) then ≤ `blink_open_max` (0.2). **Require the full close-open transition.** (EAR from mesh indices left 362,385,387,263,373,380; right 33,160,158,133,153,144 is an alternative; verify against the canonical mesh.)
  - head turn: yaw from the transformation matrix ≥ `turn_yaw_min_deg` (15°) in the requested direction. Check the sign by actually turning your head once.
- **Challenge rules** (`DECISION_POLICY.md` §7.1): the STEP_UP response carries `next_action.challenge = {nonce, actions:[a,b], step_window_ms}` (single-use nonce, TTL `challenge.session_ttl_s` 120). Exactly `steps` (2) actions in random order: **exactly one** from `deformation_actions` (SMILE / OPEN_MOUTH / PUFF_CHEEKS — mandatory) + one from `secondary_actions` (BLINK / TURN_LEFT / TURN_RIGHT). Blink-only is forbidden, because an eye-cut paper mask lets the attacker's real eyes blink. A response must start ≥ `min_reaction_ms` (150) after the prompt and complete within `step_window_ms` (1500). The kiosk submits with `POST /v1/attempt/{id}/challenge`.
  - **Hard fail → DENY `CHALLENGE_FAILED` immediately:** response before `min_reaction_ms`, wrong action, wrong turn direction, face track lost / identity switch.
  - **Soft fail** (no qualifying response in the window): one retry with a new nonce (`soft_fail_retries` 1); the second soft fail → DENY `CHALLENGE_FAILED`.
  - Step-up session older than `session_ttl_s` → DENY `CHALLENGE_FAILED`.
- The client sends the blendshape time series plus 2 key frames (neutral and peak). The server checks identity continuity (last challenge frame local cosine to the candidate ≥ `challenge.min_identity_cosine` 0.30), runs MiniFASNet on the peak frame, and optionally re-runs MediaPipe Python in IMAGE mode on the peak frame to confirm `jawOpen` or smile, since we never trust the client alone.
- **Random deformation challenge (optional hardening, R4):** with probability `challenge.random_rate` a would-be ALLOW becomes STEP_UP CHALLENGE with `RANDOM_CHALLENGE`. **The rate is 0.15 online / 0.30 offline** (the operator first asked for 0.0, then restored it: "add them back dont remove", "i want that blink and stuff"). In DEMO_MODE, `POST /v1/admin/random-challenge {mode: AUTO|FORCE_NEXT|FORCE|OFF}` forces or disables it. The RNG is injected, so tests are deterministic. Pitch: on by default (15 % / 30 %); it raises the bar for rigid masks; silicone masks remain a known RGB limit.
- Depth M1 (if depth is live): the blendshapes say "moved" but the depth is rigid → DENY `MASK_CUE_RIGID` (§8).

---

## 6. Injection detection (S0)

- **Virtual camera label:** after `getUserMedia`, call `enumerateDevices()`; labels need permission. Match the active track's label against `injection.virtual_camera_label_patterns` in the YAML (obs, virtual, manycam, snap camera, xsplit, droidcam, epoccam, camtwist, mmhmm). Candidates worth adding via `policy-engine`: splitcam, e2esoft, iriun, ndi, youcam. A match → `INJECTION_VIRTUAL_CAMERA`, hard DENY. A label not matching `known_good_label_patterns` (or empty) → `LIVENESS_UNSURE` (`unknown_label_is_unsure`). On the kiosk, also allow-list the expected `deviceId` and label in kiosk config.
- **Frame timing:** collect `requestVideoFrameCallback` metadata (`mediaTime`, `presentedFrames`, `expectedDisplayTime`). Per `DECISION_POLICY.md` §3.2, timestamps that are non-monotonic or an inter-frame interval outside [`min_frame_interval_ms` 15, `max_frame_interval_ms` 400] → `INJECTION_VIRTUAL_CAMERA` (DENY). Softer heuristics (repeated identical `mediaTime`, near-zero jitter (std < 0.2 ms) that looks synthetic, an fps that doesn't match `track.getSettings().frameRate`, a sudden resolution change) are **logged in `scores` only** — they are not policy inputs unless `DECISION_POLICY.md` adds them.
- **Nonce binding:** every upload carries the attempt `nonce` together with its own flash sequence. The edge rejects an expired nonce (`410 NONCE_EXPIRED`), a reused nonce (`409 NONCE_REUSED`; keep a set of seen nonces with a TTL), or a nonce from a different attempt/kiosk. The random flash colours and challenge order make a pre-recorded stream fail, and the nonce makes a replayed HTTP payload fail.
- Honest limit for the pitch: a real-time deepfake rendered through a trusted camera path can't be fully stopped by browser checks. The mitigation is a locked-down kiosk OS and an allow-listed camera.

---

## 7. Face matching (S5)

**Local (always available, used offline):**
- Embeddings: ArcFace or another recogniser via `uniface`, giving a 512-d L2-normalised vector. Score with cosine (dot product). InsightFace `buffalo_l` weights are **non-commercial**. For commercial cleanliness use AuraFace or EdgeFace through uniface, and say so on the licence slide. Store `model_name` and `model_version` with every template, because embeddings from different models are incompatible.
- Generic ArcFace ONNX convention: 112×112 **RGB**, `(x − 127.5) / 127.5`, NCHW. Verify this against your model's reference code. Code: R2/R7.
- 1:N search: `scores = T @ q` over a `[N, 512]` float32 matrix covering only this kiosk's users. That's sub-millisecond, so FAISS isn't needed at hackathon scale.
- Zones (`match.local`, `DECISION_POLICY.md` §3.5): PASS = top1 ≥ `allow_min_cosine` (0.50 start value [cal]; offline = calibrated + `offline.match_offline_delta` 0.05) **and** top1 − top2 ≥ `min_margin_top1_top2` (0.10; offline 0.15), top2 taken across *different* users. 0.30 ≤ top1 < allow → `MATCH_LOW` (UNSURE); top1 ≥ allow but margin too small → `MATCH_AMBIGUOUS` (UNSURE); top1 < `deny_below_cosine` (0.30) → `NOT_ENROLLED` (FAIL). First and last usable frame must give the same top-1 user, else `MATCH_AMBIGUOUS`.
- **Enrolment** (as built `edge/enroll.py`; UI `kiosk/public/enroll.html` or the admin panel): consent checkbox with DPDP text + admin token, 5 frames at up to 1280 px → `POST /v1/enroll`. Each frame must pass the edge quality checks and passive PAD (`pass_min`) with no device near the face. The set must be one identity (min pairwise cosine ≥ the local allow threshold) and must not match a *different* enrolled user. The response carries diagnostics (`frames_used`, `frames_rejected`, `min_pairwise_cosine`, `cloud_indexed`). Local enrolment works offline; Rekognition is indexed only when ONLINE. `GET /v1/admin/users` lists users; `DELETE /v1/enroll/{user_id}` erases them (local + cloud). No raw images are kept on the edge.
- **Template encryption:** Fernet (`cryptography`), one token in `edge/data/templates.fernet`. The key comes from `.env` `EDGE_DATA_KEY` (a Fernet key, base64). Decrypt into memory at startup. Template cache max age `cache.template_cache_max_age_hours` (72 h), else unusable → `NOT_ENROLLED`. Code: R7.
- **Calibration recipe** (in `eval/`: `eval/collect_faces.py` + `eval/compare.py` on consenting team photos; then `policy-engine` writes the result into `thresholds.yaml`): genuine scores = probe compared with own templates; impostor scores = probe compared with every other user (plus a public face set if you have one). Set `allow_min_cosine` to the **99.8th percentile of impostor scores** (`calibration_impostor_percentile`, target FAR 0.2 %) and record N impostor pairs and the bound in `eval/results/`. With few impostor pairs the percentile is unreliable — say so, and check the max impostor score too. Report FAR/FRR at the chosen point with the rule of 3 for zero counts (see the `pad-evaluation` skill). For 1:N, the effective FAR is about N × the per-comparison FAR, which is why the margin rule exists.

**Cloud (online, Rekognition user vectors, sandbox region us-east-1; production ap-south-1).** Code: R8.
- Consenting team faces only; the collection is deleted at teardown. If the Workshop Studio role denies Rekognition, the cloud returns `503` and the attempt follows P7 (see `cloud/SANDBOX.md`).
- Enrol: `create_collection`, then `index_faces` for each of 3-5 images (`MaxFaces=1, QualityFilter="HIGH"`), then `create_user(UserId)`, then `associate_faces(UserId, FaceIds)`.
- Auth: `search_users_by_image(CollectionId, Image={"Bytes": jpg}, MaxUsers=2, UserMatchThreshold=match.rekognition.user_match_threshold (80), QualityFilter="AUTO")`. Similarity is 0-100. Zones (`match.rekognition`, `DECISION_POLICY.md` §3.5): PASS = top1 ≥ `allow_min_similarity` (99) **and** runner-up < `runner_up_max_similarity` (80); 80 ≤ top1 < 99 → `MATCH_LOW`; top1 ≥ 99 but runner-up ≥ 80 → `MATCH_AMBIGUOUS`; no UserMatches or top1 < `deny_below_similarity` (80) → `NOT_ENROLLED`.
- Design for the stricter Mumbai default TPS (**5** for Search/Index/Associate, 25 for CompareFaces) even in us-east-1. Bangalore ↔ us-east-1 RTT is ≈ 200-250 ms, so send a small face JPEG, reuse one keep-alive client, and time-box the whole call at `latency_budget_ms.rekognition_timeout`. A timeout or error makes **the whole attempt OFFLINE** (P7: no "half-online" decisions) and records a connectivity miss.
- Fusion (online, `edge/policy/identity.py`): Rekognition is authoritative. The local matcher can only tighten: if the local top-1 is a **different user** with cosine ≥ `identity.cross_check_conflict_min_cosine` (0.50, its own key, R9) → `MATCH_AMBIGUOUS` (`match.cross_check_local_conflict`); first/last frame disagree or the local cache is unusable → `MATCH_AMBIGUOUS`.
- `match.rekognition.enabled: false` (online): no cloud match is requested; identity = the local matcher with the **offline bars** (0.55, margin 0.15), while the liveness/schedule/mode rules stay ONLINE. Decisions are always made on the edge.

---

## 8. Optional iPhone TrueDepth depth (`depth/`, DepthProbe)

- Use the **front TrueDepth** camera, not the rear LiDAR. Continuity Camera gives RGB only. The DepthProbe SwiftUI app (`depth/ios/`, v0.2.0, sideloaded as an unsigned IPA, connected) long-polls `GET /v1/depth/pending` (which returns a `depth_nonce`), captures 1-3 synchronised depth frames (+1 JPEG, intrinsics, depth type, `accuracy` absolute|relative) **during the capture window** (and one during the mouth challenge for M1) and pushes them with `POST /v1/depth/frames` (echoing `depth_nonce`; mismatch or reuse → 403) to the edge's LAN listener `0.0.0.0:EDGE_LAN_PORT` (8001), which serves only these two routes and requires `X-Depth-Token` == `DEPTH_DEVICE_TOKEN`. **Depth stays disabled until the H4 calibration (`python -m depth.calibrate`, ≥ 10 live vs ≥ 10 printed photo) reports GO** (`docs/IPHONE_SETUP.md`). Python (`depth/checks.py`, via `edge/depth_bridge.py`) computes the checks. The edge waits at most `latency_budget_ms.depth_max_wait` after the RGB frames; later depth → `NOT_AVAILABLE` (no effect). Depth maps stay in RAM. Depth is used only when `liveness.depth.enabled: true`.
- Checks (`liveness.depth` and `liveness.mask` in the YAML; values marked [est]):
  - D0: valid depth in the face ROI. < `d0_valid_fail_below` (0.40) → `QUALITY_DEPTH_INVALID` (recapture); [0.40, `d0_valid_pass_min` 0.60) → `LIVENESS_UNSURE`.
  - D1: plane-fit RMS. < 3 mm → FAIL; > 6 mm → pass; between → UNSURE.
  - D2: quadratic-surface residual. < 2 mm → FAIL (bent paper); > 4 mm → pass.
  - D3: nose relief (cheeks median minus nose tip). < 8 mm → FAIL; ≥ 15 mm → pass.
  - D1-D3 FAIL → `SPOOF_FLAT_DEPTH` (hard DENY).
  - D4: metric inter-pupil distance outside 45-80 mm → `SPOOF_DEPTH_SCALE` (hard DENY). Needs absolute depth (`require_absolute_depth_for_d4`); log `depthDataAccuracy` and skip D4 if depth is relative.
  - M1: rigid-align forehead and nose bridge between the neutral and deformation frames. Mouth/cheek residual < `m1_mouth_residual_min_mm` (4 mm) while the blendshapes say "moved" → **DENY `MASK_CUE_RIGID`** (decisive). Real: mouth > 4 mm while forehead < `m1_forehead_residual_max_mm` (2 mm).
  - M2: RGB Laplacian ring score ≥ 0.50 (weak) / ≥ 0.75 (strong), or depth step ≥ 10 mm around the eye holes / face edge (strong) → `MASK_CUE_EDGE`.
  - M3: RMS against the enrolled depth template ≥ 6 mm (weak) / ≥ 8 mm (strong) → `MASK_CUE_SHAPE`.
  - Rules (`DECISION_POLICY.md` §3.4): **≥ `strong_cue_deny_count` (2) strong cues → DENY**; ≥ 1 cue (weak or strong) and < 2 strong → STEP_UP CHALLENGE (with deformation).
- Code: R9 (plane-fit RMS, quadratic residual, nose relief).
- Xcode builds: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` (xcode-select still points at the Command Line Tools; no sudo). The free-team profile from this Mac is banned on the device, so we ship an **unsigned IPA** (`depth/ios/dist/DepthProbe-0.2.0.ipa`) that the operator sideloads and re-signs with their own tool. The iOS Simulator has no TrueDepth camera — compile/UI checks only.
- **Go/no-go at hour 4:** DepthProbe runs on the physical phone, a depth result reaches the edge for a real attempt, **and** D1 rejects a printed photo while passing a teammate. If any fails, drop the feature to a roadmap slide. Don't let it eat the critical path. Keep the device indoors (sunlight washes out IR) and on power.

---

## 9. Policy engine (S6). This is where judges poke.

- Write it as **pure, deterministic functions** in `edge/policy/` (owned by `policy-engine`): `evaluate(att, ctx)`, `biometric_result()`, `combine()`, `resolve_stepup()` as in `DECISION_POLICY.md` §11. All I/O (models, cloud, DB), the clock and the RNG (random challenge) are injected through `ctx`, so tests are deterministic and the cloud `/v1/sync` can re-evaluate offline decisions with the same `evaluate_schedule`.
- **Write the tests first**: `edge/policy/tests/` (and `edge/offline/tests/` for store/sync/connectivity), parametrised from `docs/POLICY_TEST_CASES.md`. Each row there becomes one case, and the test asserts `decision`, the **set** of `reason_codes`, and `next_action.steps` / `methods` where listed. The property tests P01-P08 (no hard-spoof input ever gives ALLOW; OFFLINE never more permissive than ONLINE; engine never raises; missing signals never pass, ...) are mandatory.
- Evaluation order (authoritative: `DECISION_POLICY.md` §2):
  0. Rate limit → DENY `RATE_LIMITED` (`next_action` NONE, `retry_after_s`).
  1. Quality gate → STEP_UP RECAPTURE, or the D4 exhausted path (§1).
  2. Injection → DENY `INJECTION_VIRTUAL_CAMERA`.
  3. Liveness fusion ‖ 4. identity match (parallel).
  5. Biometric result: any hard spoof code or ≥ 2 strong mask cues → BIO_FAIL (DENY); identity FAIL → BIO_FAIL `NOT_ENROLLED`; any liveness UNSURE / mask cue / identity UNSURE → BIO_UNSURE; else BIO_PASS. The random challenge (rate 0.15 online / 0.30 offline) may convert a would-be ALLOW to STEP_UP CHALLENGE `RANDOM_CHALLENGE`.
  Any exception or unknown enum anywhere → DENY `SYSTEM_ERROR` (R14; never HTTP 500, no `assert` for P9).
  6. **SC1 schedule** — only for BIO_PASS / BIO_UNSURE.
  7. **SC2 mode restrictions** (`DECISION_POLICY.md` §8).
  8. Final decision + reason codes + `next_action`.
  Reason-code composition follows `DECISION_POLICY.md` §6 exactly (e.g. on BIO_FAIL the unsure codes are **not** added; on ALLOW the step-up triggers move to `resolved_codes`). Severity `DENY > STEP_UP > ALLOW`; each later stage can only keep or tighten (P4).
- `next_action` (`DECISION_POLICY.md` §7) tells the UI what to offer: `type` ∈ OPEN_DOOR / RECAPTURE / CHALLENGE / SECOND_FACTOR / CONTACT_DESK / NONE, ordered `steps`, `methods` ⊆ {TOTP, CARD, EMAIL_OTP (online only), STAFF_OVERRIDE} from `stepup.methods`, and the `challenge` block. A successful step-up goes through `resolve_stepup()`; it never bypasses the policy and never overrides a DENY.
- **Rate limiter (D3, R1; `edge/policy/ratelimit.py`):** counts **only attack-evidence DENYs** (`SPOOF_*`, `MASK_CUE_RIGID` / strong-mask DENY, `INJECTION_VIRTUAL_CAMERA`, `CHALLENGE_FAILED`, `FALLBACK_FAILED`; YAML `rate_limit.counted_code_prefixes` + `counted_codes`; a DENY carrying a `SCHEDULE_*` code is not counted); never schedule / identity / quality / `SYSTEM_ERROR` / `RATE_LIMITED` DENYs. `rate_limit.max_failures` (5) in `window_s` (180 s) → `lockout_s` (**5 s**, operator request; was 60) of DENY `RATE_LIMITED` + an alert. `rate_limit.enabled` (true by default; an eval/demo profile may disable it); reset with `POST /v1/admin/rate-limit/reset`.
- Skeleton: R10.

### SC1: campus schedule evaluator
- Input: the signed bundle in `config/schedule.example.json` format (roles, users with `zones_add` / `zones_remove` / `extra_windows`, zones with `risk`, holidays, exceptions, visitor passes, revocations). The cloud holds the authoritative copy and issues signed per-kiosk bundles.
- `evaluate_schedule(user_id, zone, t0, bundle, T.schedule)` in `edge/policy/schedule.py` is a pure function; **online and offline use the same function on the newest signed bundle** (D2; no per-attempt cloud schedule call). Online with a bundle older than `schedule.online_max_bundle_age_min` (30) → the attempt is OFFLINE (P7, mode reason `bundle_stale`). Revocation is time-aware (`revoked_at` ≤ t0) and checked first. Use `zoneinfo.ZoneInfo("Asia/Kolkata")` and test the window edges (start and end minute, midnight-spanning windows, grace not leaking across midnight).
- Results, first match wins (`DECISION_POLICY.md` §5): `REVOKED` → `NO_ENTITLEMENT` → `ZONE_NOT_PERMITTED` → `HOLIDAY` → `IN_WINDOW` → `GRACE_WINDOW` (± `grace_minutes` 15; `grace_minutes_high_risk` 0) → `OUTSIDE_WINDOW`. Codes: `SCHEDULE_REVOKED`, `SCHEDULE_NO_ENTITLEMENT`, `SCHEDULE_ZONE_NOT_PERMITTED`, `SCHEDULE_HOLIDAY`, `SCHEDULE_GRACE_WINDOW`, `SCHEDULE_OUTSIDE_WINDOW`; IN_WINDOW adds none.
- Combination (matrix rows N1-N13): BIO_PASS + IN_WINDOW → ALLOW (low/medium zone) or STEP_UP `SCHEDULE_HIGH_RISK_ZONE` (high-risk, online, while `schedule.high_risk_requires_stepup_online` is true, R8); GRACE → STEP_UP SECOND_FACTOR; deny-type → DENY; BIO_UNSURE + anything but IN_WINDOW → DENY. A live, recognised person is **not** automatically authorised.

### SC2: offline mode
- **Detection** (owner `policy-engine`, `edge/offline/connectivity.py`; values in `connectivity:`): heartbeat `GET {CLOUD_API_URL}/v1/health` (`connectivity.health_path`) every `heartbeat_interval_s` (5 s, timeout 2000 ms); `misses_to_offline` (3) consecutive misses → OFFLINE (natural detection about 12–17 s after the link drops); any cloud failure inside an attempt makes **that attempt** OFFLINE immediately (P7). `successes_to_online` (3) → SYNCING (still offline rules) → ONLINE only after the queue is acknowledged and a fresh bundle + revocations are installed. State at `GET /v1/mode` (the kiosk badge polls it every 2 s); demo switch `POST /v1/admin/mode {"force": "OFFLINE"|"AUTO"}` (immediate).
- **Signed bundle:** HMAC-SHA256 over canonical JSON with `SCHEDULE_BUNDLE_HMAC_KEY` (hackathon); Ed25519 in production (kiosk holds only the public key); never KMS/ECDSA. Signer (`scripts/sign_bundle.py`, source `config/schedule.demo.json` / cloud) stamps `issued_at` = now, `expires_at` = now + 12 h, override codes `valid_until` = `expires_at` + `fallback.staff_override.valid_after_expiry_h` (24 h, R7). Verify with `hmac.compare_digest`. **Last valid bundle (R6):** a received bundle that fails verification is rejected (alert) and never replaces the LVB; a file tampered on disk is rejected and the in-memory LVB stays; override codes and kiosk zone/risk always come from the LVB. Refreshed every `cache.bundle_refresh_interval_min` (15) online + revocations at each heartbeat. Effective expiry = min(`expires_at`, `issued_at` + `bundle_max_staleness_hours` 12 h). INVALID only when there is no LVB or the clock rolled back (now < `issued_at` − `cache.clock_rollback_tolerance_s` 300 s).
- **Offline rules** (`DECISION_POLICY.md` §8.2; SYNCING uses them too): always add `OFFLINE_MODE`; stricter `offline.overrides` (PAD 0.85, flash r 0.75, ambient exception off, match 0.55, margin 0.15; random challenge stays 0.0); UNSURE → CHALLENGE (if liveness cause) **+ SECOND_FACTOR always** (`OFFLINE_FALLBACK_REQUIRED`); high-risk zone (or risk above `offline.auto_allow_max_risk` = medium) → STEP_UP `OFFLINE_HIGH_RISK_ZONE`, methods TOTP / STAFF_OVERRIDE (no per-zone offline DENY); bundle EXPIRED → deny-type still DENY (+`SCHEDULE_EXPIRED_CACHE`), IN_WINDOW/GRACE → STAFF_OVERRIDE only; clock rolled back with an LVB → no schedule, STEP_UP `SCHEDULE_BUNDLE_INVALID`, STAFF_OVERRIDE only (`stepup.methods.cache_untrusted`); **no LVB at all → BIO_PASS/UNSURE → DENY `SCHEDULE_BUNDLE_INVALID` CONTACT_DESK** (zone `"UNKNOWN"`, R6). The only automatic offline ALLOW is BIO_PASS + IN_WINDOW + FRESH + low/medium-risk (row F1).
- **Fallback verification** (`fallback:`, `DECISION_POLICY.md` §7.2; `edge/policy/fallback.py`): TOTP (RFC 6238, ±1 step) against **real wall time, never the demo clock**, per-user secret in the encrypted local credentials, last accepted step stored per user (replay → `FALLBACK_FAILED`), and the logged `totp_step` (not secret) lets the cloud detect cross-kiosk replay (Y07); CARD = HMAC-SHA256(`CARD_ID_PEPPER`, card_id) vs `card_id_hash`; STAFF_OVERRIDE = one-time 8-digit code, PBKDF2-HMAC-SHA256 (100 000 it.) vs unused hashes in the bundle, `staff_id` recorded, 3 wrong codes → locked 300 s. `stepup.max_attempts_per_step` (2) per step, then DENY `FALLBACK_FAILED`. EMAIL_OTP via SES is **online only**.
- **Minimal temporary storage** (`SURPRISE_CHALLENGES.md` §SC2.5, exactly those fields): `attempt_id, seq, kiosk_id, zone, ts_utc, user_id, candidate_user_id, decision, reason_codes, resolved_codes, scores (rounded to 2 dp), fallback {method, staff_id, code_id, totp_step}, schedule_version, cache_state, mode, prev_hash, record_hash`. AES-GCM / Fernet encrypted SQLite `decision_log` (online and offline use the same queue). **No images, crops, depth maps, embeddings, display names, TOTP values or raw card IDs.** Purge on sync ack; unsynced records purged at `offline_store.max_retention_hours` (24 h) leaving a tombstone `{count, first_seq, last_seq, chain_head}`.
- **Sync queue:** idempotency key = `attempt_id` (`att_<ulid>`). On reconnect the sync agent POSTs batches of ≤ `sync.batch_size` (50) in `seq` order to the cloud `POST /v1/sync` (contract: `docs/API.md` v1.1: `{kiosk_id, batch_id, kiosk_now_utc, items (records + TOMBSTONE items), chain_head, chain_head_hmac}` → `{accepted, duplicates, rejected, flags}`), backoff 1 → 60 s ±20 %. The cloud stores idempotently, verifies the hash chain, re-evaluates offline ALLOWs against the authoritative schedule and revocations at `ts_utc`, and raises `ALERT_*` (e.g. `ALERT_REVOKED_USER_ADMITTED`, `ALERT_OVERRIDE_REUSE`, `ALERT_LOG_TAMPER`; SC2.6). Delete rows only on acknowledgement.
- **Hash chain:** `record_hash = SHA256(prev_hash || canonical_json(record))`, canonical = `json.dumps(sort_keys=True, separators=(",",":"))`; genesis `prev_hash = SHA256("genesis:" + kiosk_id)`; the chain head is HMAC'd with the kiosk key at each sync. A chain break means tampering. Code: R11.
- **Demo clock (D8, R18):** `POST /v1/admin/clock` (only with `DEMO_MODE=1`) takes `{set_local: "HH:MM"}` | `{offset_s}` | `{reset: true}` and drives the edge's schedule clock. The kiosk shows a **DEMO CLOCK** badge. It does **not** re-sign the bundle: a demo time earlier than `issued_at` − 300 s reads as clock rollback (INVALID). So use **evening times** with a bundle signed the same day (e.g. LIBRARY 21:10 = grace STEP_UP, 21:30 = outside DENY). TOTP ignores the demo clock. Reset it before the SC2 demo segment.

---

## 10. Latency discipline (≤ 2 s face-lock → decision)

- Measure every stage with a `perf_counter` context manager. Return `latency_ms{quality, liveness, match, schedule, policy, total}` and log them as UTC JSON lines. The browser measures face-lock → decision rendered with `performance.now()` and reports it with `POST /v1/attempt/{id}/rendered`; that is the number that goes on slides (p50 and p95 with bootstrap CI, next to server `latency_ms.total`, per the `pad-evaluation` skill).
- Run **liveness and matching concurrently**: `await asyncio.gather(loop.run_in_executor(pool, liveness, ...), loop.run_in_executor(pool, match, ...))` on a `ThreadPoolExecutor(max_workers=4)`. ONNX Runtime releases the GIL. Set `intra_op_num_threads=2` per session so that parallel sessions don't oversubscribe the CPU. Code: R12.
- **Warm everything at startup** in the FastAPI `lifespan`: load the ONNX sessions once (as module singletons), run one dummy inference per model, open the cloud HTTP client (keep-alive) and make one cheap call, and load the template cache. On the browser side, preload `face_landmarker.task` and the WASM before the first user arrives.
- **Measured (dev measurement, n = 32, offline, MacBook webcam; not an eval result):** kiosk face lock → rendered p50 1518 ms / p95 1559 ms; edge server total p50 127 ms / p95 154 ms. The 1000 ms capture window in use at the time dominated; it is now 700 ms (`liveness.flash.duration_ms`), so re-measure. Online adds the cloud match (time box 700 ms, not measured yet), so an online attempt near the time box could be over 2 s: measure before claiming. Upload = 5 JPEGs at up to 1280 px. Depth arrives during the capture window (no pull).
- The cloud call is never on the critical path without a time box (`latency_budget_ms.rekognition_timeout`). If it's slow or fails, the attempt is decided with the local matcher under OFFLINE rules (P7) — there is no "degraded" third mode.

---

## 11. Common pitfalls (check this list before debugging anything else)

1. **Wrong MiniFASNet crop scale.** V2 is 2.7×, V1SE is 4.0×, the result goes to 80×80, and the box is shifted inside the image rather than shrunk. Feeding the aligned 112 crop gives meaningless scores.
2. **Wrong "real" output index, or wrong normalisation** (0-255 vs /255). Run the startup self-test on real and print fixtures.
3. **BGR/RGB mix-ups.** MiniFASNet expects BGR (straight from `cv2.imdecode`). ArcFace usually expects RGB. Browser canvas `ImageData` is RGBA. Decode JPEGs with OpenCV on the server and convert explicitly at each model boundary.
4. **Mirrored frames.** Mirror only the preview. Uploading mirrored frames flips left/right turns and blendshape sides, and slightly hurts matching against unmirrored enrolment images.
5. **Auto-exposure and white balance** wash out the flash signal and change blur and luma between frames. Lock them where you can, use chromaticity rather than raw RGB, and treat a weak signal as unsure.
6. **Cold start.** The first inference is 5-10× slower. Warm up in `lifespan`, keep EC2 warm, and avoid Lambda cold starts on the main path.
7. **Sandbox limits and distance.** The AWS Workshop Studio sandbox allows **us-east-1 only** and its event IAM role may deny Rekognition, SES, DynamoDB, KMS or IAM — verify with `cloud/infra/probe_sandbox.sh` in the first 30 minutes and use the degraded path for anything denied. Design for the Mumbai default quotas (Search/Index 5 TPS; Face Liveness 5 TPS, 15 concurrent). Bangalore ↔ us-east-1 RTT ≈ 200-250 ms. SMS to India needs TRAI DLT, which we can't get today, so use SES email (SES sandbox: verified recipients only) or TOTP.
8. **Licences.** Ultralytics is AGPL. InsightFace weights are non-commercial. CelebA-Spoof-trained models (facenox) are non-commercial. The ekyc flash code has no licence, so don't copy it. MiniFASNet originals are Apache-2.0. Keep `docs/LICENSES.md` current for the slide.
9. **Threshold drift.** Thresholds belong only in `config/thresholds.yaml` (owner `policy-engine`). Log `policy_version` (and `bundle_version`) with every decision.
10. **Fail-open bugs.** A `try/except` that returns `True` or a pass. A missing signal treated as a pass. An unsure result that maps to ALLOW offline. The property tests P01-P08 exist to catch these.
11. **Timezone bugs.** Server clocks in UTC versus schedules in IST. Always convert explicitly, and test window edges. With the demo clock active, every component must read the injected clock, not `datetime.now()`.
12. **Detector box format.** Some return `(x1,y1,x2,y2)` and others `(x,y,w,h)`. Normalise once in S3.
13. **Blink-only step-up.** Never allow it; there must always be exactly one mouth or cheek action.
14. **Trusting client scores.** The client's blendshapes and ROI series are cross-checked; they are never decisive on their own.
15. **Non-canonical codes or endpoints.** Only the codes in `DECISION_POLICY.md` §6 (= `edge/policy/codes.py`) and the endpoints in `docs/API.md` v1.1 exist. Retired: `/v1/authenticate`, top-level `/v1/challenge`, `/v1/stepup`, `/v1/fallback/verify`, `/v1/enrol`, `/v1/attempts/{id}`, `/status`, `/admin/connectivity`, `/v1/sync/decisions`. No `STAGE_ERROR_*`, `DEGRADED` or `FLASH_*` reason codes.
16. **Over-claiming.** Say "iBeta Level 1-style protocol" (never "certified"), report 0/N results as an upper bound (rule of 3), say depth "raises the bar", and that silicone masks are a known RGB limit. While `liveness.flash.enforce` is false, never say the colour flash blocks replays. Dev measurements are labelled "dev", never shown as eval results. See `CLAUDE.md` §8.
17. **Testing against the live edge.** The operator's demo edge runs on `127.0.0.1:8000`. Start your own instance on another port (e.g. `--port 8100`, with its own `EDGE_DATA_DIR`) for tests, and never reset, reconfigure or load-test `:8000`.

## 12. File layout (as built; ownership per `docs/BUILD_PLAN.md` §2)

```
edge/app.py                 FastAPI routes + LAN listener (0.0.0.0:EDGE_LAN_PORT, /v1/depth/* only), lifespan warm-up (edge-ml)
edge/schemas.py             HTTP models (CaptureSpec max_width_px 1280, DepthFramesMeta, EvalContext, ClockRequest)
edge/attempts.py            per-attempt orchestration: liveness_branch || match_branch || depth_branch
edge/session.py             attempt ids, nonces (TTL 10 s), flash sequence (3 colours)   edge/config.py  .env + YAML
edge/perception.py, edge/ml/{detect,quality,pad,device,moire,flash,mask,matcher,templates,onnx,registry}.py   signals
edge/cloud_client.py        cloud calls, time-boxed     edge/depth_bridge.py   DepthProbe jobs, depth_nonce, checks
edge/enroll.py              liveness-gated enrolment    edge/events.py, edge/metrics.py   SSE feed, /v1/metrics
edge/policy/{engine,runtime,liveness,identity,quality,injection,schedule,stepup,challenge,fallback,ratelimit,codes,signals,thresholds}.py   (policy-engine)
edge/offline/{connectivity,store,bundle,sync,signing,crypto,credentials}.py   SC2 (policy-engine)
edge/policy/tests/ (test_cases.py = POLICY_TEST_CASES vectors), edge/offline/tests/, edge/tests/
kiosk/src/{kiosk,capture,api,admin,shared}/   kiosk UI + dashboard;  kiosk/public/enroll.html  enrolment page (kiosk-frontend)
cloud/app/{main,auth,canonical,...}.py, cloud/app/routers/, cloud/app/services/   cloud API;  cloud/infra/*.sh  deploy (cloud-aws)
depth/ios/DepthProbe/       SwiftUI app (unsigned IPA in depth/ios/dist/)   depth/checks.py  D0-D4, M1-M3
depth/calibrate.py          H4 calibration CLI (serve / summary / synth)      (depth-iphone)
eval/capture.py, eval/metrics.py, eval/summary.py, eval/scenarios/   evaluation (eval-metrics)
scripts/sign_bundle.py      HMAC bundle signer (policy-engine); scripts/fetch_models.sh, bench_latency.py (edge-ml)
```
