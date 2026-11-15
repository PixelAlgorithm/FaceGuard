# liveness-kiosk: code reference (R1-R12)

> **UPDATE (2026-11-14, as built):** the real implementations now exist and **win over these sketches**:
> quality `edge/ml/quality.py` + `edge/policy/quality.py`; PAD `edge/ml/pad.py`; device/moiré `edge/ml/device.py`,
> `edge/ml/moire.py`; flash `edge/ml/flash.py`; matcher `edge/ml/matcher.py` + `edge/ml/templates.py`; Rekognition
> `cloud/app/services/faces.py` + `match_service.py`; depth `depth/checks.py` (DepthProbe frames); policy
> `edge/policy/engine.py` + `runtime.py`; bundle/log/sync `edge/offline/{bundle,store,sync}.py`; orchestration
> `edge/attempts.py`. Record3D streaming is paid and NOT used: depth comes from our own SwiftUI app **DepthProbe**
> (`depth/ios/`, see `docs/IPHONE_SETUP.md`). Reason codes are the closed list in `edge/policy/codes.py`
> (= `DECISION_POLICY.md` §6). R1–R7 below are pre-build sketches whose literals may be stale; read the YAML key.


This is original code written for this project. It is meant as a starting point, so adapt the names to the
scaffold. Every threshold is read from `cfg` (loaded from `config/thresholds.yaml`). Literals in the
code are only defaults for illustration.

---

## R1. Quality gate (server)

```python
import cv2, numpy as np

def luma_stats(bgr: np.ndarray, box) -> tuple[float, float]:
    x1, y1, x2, y2 = map(int, box)
    roi = cv2.cvtColor(bgr[y1:y2, x1:x2], cv2.COLOR_BGR2GRAY)
    clipped = float(((roi < 10) | (roi > 245)).mean())
    return float(roi.mean()), clipped

def blur_score(aligned112_bgr: np.ndarray) -> float:
    g = cv2.cvtColor(aligned112_bgr, cv2.COLOR_BGR2GRAY)
    return float(cv2.Laplacian(g, cv2.CV_64F).var())

def pose_from_kps(kps5: np.ndarray) -> dict:
    """kps5: [[lx,ly],[rx,ry],[nose],[lmouth],[rmouth]] in image px (image-left eye first)."""
    le, re, nose = kps5[0], kps5[1], kps5[2]
    eye_mid = (le + re) / 2
    iod = float(np.linalg.norm(re - le)) + 1e-6
    roll = float(np.degrees(np.arctan2(re[1] - le[1], re[0] - le[0])))
    yaw_proxy = float((nose[0] - eye_mid[0]) / iod)    # ~0 frontal, ±0.25 ≈ 15-20°
    pitch_proxy = float((nose[1] - eye_mid[1]) / iod)  # neutral ≈ 0.5-0.7; calibrate offset
    return {"iod": iod, "roll": roll, "yaw_proxy": yaw_proxy, "pitch_proxy": pitch_proxy}

def quality_gate(bgr, faces, aligned, cfg) -> dict:
    """faces: list of (box_xyxy, score, kps5) from the detector, sorted by area desc."""
    q, reasons = cfg["quality"], []
    faces = [f for f in faces if f[1] >= q["det_score_min"]]
    if not faces:
        return {"ok": False, "reasons": ["NO_FACE"]}
    main = faces[0]
    a0 = (main[0][2] - main[0][0]) * (main[0][3] - main[0][1])
    if any((f[0][2]-f[0][0])*(f[0][3]-f[0][1]) > q["second_face_area_ratio"] * a0 for f in faces[1:]):
        reasons.append("MULTIPLE_FACES")
    h_img, w_img = bgr.shape[:2]
    box, _, kps = main
    face_h = box[3] - box[1]
    pose = pose_from_kps(np.asarray(kps))
    if face_h < q["face_min_px"] or pose["iod"] < q["iod_min_px"]:
        reasons.append("FACE_TOO_SMALL")
    m = q["edge_margin_frac"]
    if box[0] < m*w_img or box[1] < m*h_img or box[2] > (1-m)*w_img or box[3] > (1-m)*h_img:
        reasons.append("FACE_TRUNCATED")
    blur = blur_score(aligned)
    if blur < q["blur_min"]:
        reasons.append("BLURRY")
    y, clipped = luma_stats(bgr, box)
    if y < q["luma_min"]: reasons.append("LOW_LIGHT")
    if y > q["luma_max"]: reasons.append("OVEREXPOSED")
    if clipped > q["clipped_max"]: reasons.append("BACKLIT_OR_CLIPPED")
    if abs(pose["roll"]) > q["roll_max_deg"] or abs(pose["yaw_proxy"]) > q["yaw_proxy_max"]:
        reasons.append("POSE")
    return {"ok": not reasons, "reasons": reasons, "blur": blur, "luma": y,
            "clipped": clipped, "face_px": float(face_h), "n_faces": len(faces), **pose}
```

## R2. 5-point alignment to 112×112 (for the matcher only)

```python
ARCFACE_DST = np.array([[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366],
                        [41.5493, 92.3655], [70.7299, 92.2041]], dtype=np.float32)

def align112(bgr: np.ndarray, kps5: np.ndarray) -> np.ndarray:
    M, _ = cv2.estimateAffinePartial2D(np.asarray(kps5, np.float32), ARCFACE_DST, method=cv2.LMEDS)
    return cv2.warpAffine(bgr, M, (112, 112), borderValue=0)
```
If you use uniface's own alignment helper, use that instead and don't mix the two.

## R3. MiniFASNet (onnxruntime): crop, inference, fusion, voting

```python
import onnxruntime as ort

def _session(path: str, threads: int = 2) -> ort.InferenceSession:
    so = ort.SessionOptions()
    so.intra_op_num_threads = threads
    so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    return ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])

def scaled_crop(bgr: np.ndarray, box_xywh, scale: float, out: int = 80) -> np.ndarray:
    """Mirror of minivision CropImage semantics: enlarge around centre, shift (not shrink) into image."""
    H, W = bgr.shape[:2]
    x, y, w, h = box_xywh
    scale = min((H - 1) / h, (W - 1) / w, scale)
    nw, nh = w * scale, h * scale
    cx, cy = x + w / 2, y + h / 2
    x1, y1, x2, y2 = cx - nw / 2, cy - nh / 2, cx + nw / 2, cy + nh / 2
    if x1 < 0: x2 -= x1; x1 = 0
    if y1 < 0: y2 -= y1; y1 = 0
    if x2 > W - 1: x1 -= x2 - (W - 1); x2 = W - 1
    if y2 > H - 1: y1 -= y2 - (H - 1); y2 = H - 1
    crop = bgr[int(y1):int(y2) + 1, int(x1):int(x2) + 1]
    return cv2.resize(crop, (out, out))          # stays BGR

def _softmax(v: np.ndarray) -> np.ndarray:
    if np.all(v >= 0) and abs(v.sum() - 1) < 1e-3:   # already probabilities
        return v
    e = np.exp(v - v.max()); return e / e.sum()

class MiniFAS:
    def __init__(self, cfg):
        m = cfg["fas"]
        self.models = [(_session(m["v2_path"]), 2.7), (_session(m["v1se_path"]), 4.0)]
        self.real_idx = m["real_index"]          # expected 1; verified by self-test
        self.input_scale = m["input_scale"]      # 1.0 (raw 0-255) or 1/255; verified by self-test

    def live_prob(self, bgr, box_xywh) -> float:
        acc = np.zeros(3, np.float32)
        for sess, s in self.models:
            x = scaled_crop(bgr, box_xywh, s).astype(np.float32) * self.input_scale
            x = np.transpose(x, (2, 0, 1))[None]
            out = sess.run(None, {sess.get_inputs()[0].name: x})[0][0]
            acc += _softmax(out.astype(np.float32))
        return float(acc[self.real_idx] / len(self.models))

    def warmup(self):
        self.live_prob(np.zeros((480, 640, 3), np.uint8), (270, 190, 100, 100))

def fas_vote(probs: list[float], cfg) -> dict:
    f = cfg["fas"]
    if len(probs) < f["min_frames"]:
        return {"status": "unsure", "reason": "FAS_TOO_FEW_FRAMES", "probs": probs}
    votes = sum(p >= f["hi"] for p in probs)
    med = float(np.median(probs))
    if med <= f["lo"]:
        status = "fail"
    elif votes >= f["k_of_n"]:        # e.g. 3 (of up to 5)
        status = "pass"
    else:
        status = "unsure"
    return {"status": status, "votes": votes, "median": med, "probs": probs}

def fas_self_test(fas: MiniFAS, live_imgs, attack_imgs, detect) -> None:
    """Call at startup / in pytest. detect(img) -> box_xywh. Raises if ordering is inverted."""
    lp = np.mean([fas.live_prob(i, detect(i)) for i in live_imgs])
    ap = np.mean([fas.live_prob(i, detect(i)) for i in attack_imgs])
    if not lp > ap:
        raise RuntimeError(f"MiniFAS self-test failed: live={lp:.3f} attack={ap:.3f}. "
                           "Check real_index / input_scale / crop scale / BGR.")
```

**As built (`edge/policy/liveness.py`, R11), the voting differs from the median rule above.** PASS needs
≥ `liveness.pad.min_pass_frames` (3) frames with P_live ≥ `pass_min` (0.80; offline 0.85) **and** at most 1 frame ≤
`fail_max` (0.30). FAIL (`SPOOF_PASSIVE`) = a strict majority of usable frames ≤ `fail_max`. Anything else is UNSURE
(`LIVENESS_UNSURE` → STEP_UP CHALLENGE; doc row L04). Self-test result on our weights: output index 1 = real, input raw
0-255 BGR.

## R4. Device detector rule + moiré FFT

```python
DEVICE_LABELS = {"cell phone", "laptop", "tv"}       # COCO-80 idx 67 / 63 / 62

def device_rule(dets, face_xyxy, cfg) -> dict:
    """dets: list of (label, conf, xyxy) from YOLOX / EfficientDet-Lite (Apache-2.0)."""
    fx1, fy1, fx2, fy2 = face_xyxy
    cx, cy = (fx1 + fx2) / 2, (fy1 + fy2) / 2
    w, h = fx2 - fx1, fy2 - fy1
    exp = (cx - w, cy - h, cx + w, cy + h)           # face box expanded 2x
    best = {"label": None, "conf": 0.0, "overlaps_face": False}
    for label, conf, (x1, y1, x2, y2) in dets:
        if label not in DEVICE_LABELS or conf < cfg["device"]["conf_min"]:
            continue
        contains = x1 <= cx <= x2 and y1 <= cy <= y2
        overlaps = contains or _iou((x1, y1, x2, y2), exp) >= cfg["device"]["iou_min"]
        if overlaps or conf > best["conf"]:
            best = {"label": label, "conf": float(conf), "overlaps_face": bool(overlaps)}
            if overlaps:
                break
    return best

def _iou(a, b) -> float:
    ix = max(0, min(a[2], b[2]) - max(a[0], b[0])); iy = max(0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    ua = (a[2]-a[0])*(a[3]-a[1]) + (b[2]-b[0])*(b[3]-b[1]) - inter
    return inter / ua if ua > 0 else 0.0

_N = 128
_WIN = np.outer(np.hanning(_N), np.hanning(_N)).astype(np.float32)
_yy, _xx = np.mgrid[-_N // 2:_N // 2, -_N // 2:_N // 2]
_R = np.hypot(_xx, _yy) / (_N / 2)                    # 0 at DC, 1 at Nyquist (axis)

def moire_features(face_bgr: np.ndarray, r_hf: float = 0.35) -> dict:
    g = cv2.resize(cv2.cvtColor(face_bgr, cv2.COLOR_BGR2GRAY), (_N, _N)).astype(np.float32)
    g -= g.mean()
    P = np.abs(np.fft.fftshift(np.fft.fft2(g * _WIN))) ** 2
    band = (_R > r_hf) & (_R <= 1.0)
    hf_ratio = float(P[band].sum() / (P[(_R > 0.02) & (_R <= 1.0)].sum() + 1e-9))
    logb = np.log1p(P[band])
    peak = float(logb.max() / (np.median(logb) + 1e-6))
    return {"hf_ratio": hf_ratio, "peak": peak}
```
**As built (`edge/ml/device.py` YOLOX-Tiny + `edge/policy/liveness.py`, R10):** a device box with conf ≥
`liveness.device_detector.fail_conf` (0.40) that contains ≥ `face_containment` (0.80) of the face →
`SPOOF_DEVICE_DETECTED`. **Any overlapping device box with conf ≥ `unsure_conf` (0.25) that is not a FAIL → UNSURE**
(`LIVENESS_UNSURE`). Moiré uses `liveness.moire.unsure_score` / `fail_score` (the `hf_ratio_max` / `peak_max` names
below do not exist in the YAML).

Calibrate `liveness.moire.unsure_score` / `fail_score` on about 20 live captures and about 20 phone replays at kiosk distance, using the same JPEG quality.

## R5. Colour-flash correlation (server). Original implementation.

```python
from dataclasses import dataclass
import numpy as np

@dataclass
class FlashResult:
    status: str            # pass | fail | unsure
    ncc: float
    lag_ms: float
    amplitude: float
    n_used: int
    reason: str | None

def _chroma(rgb: np.ndarray) -> np.ndarray:
    s = rgb.sum(axis=1, keepdims=True)
    return rgb / np.maximum(s, 1e-6)

def _expected(t_ms: np.ndarray, seq: list[tuple[tuple[float, float, float], float]],
              t0_ms: float, settle_ms: float) -> tuple[np.ndarray, np.ndarray]:
    """Emitted colour at each (lag-shifted) sample time; mask drops samples near transitions."""
    starts = t0_ms + np.concatenate([[0.0], np.cumsum([d for _, d in seq])])
    exp = np.zeros((len(t_ms), 3)); ok = np.zeros(len(t_ms), bool)
    for i, (rgb, _) in enumerate(seq):
        m = (t_ms >= starts[i] + settle_ms) & (t_ms < starts[i + 1])
        exp[m] = rgb; ok |= m
    return exp, ok

def _ncc(a: np.ndarray, b: np.ndarray) -> float:
    a = a - a.mean(axis=0); b = b - b.mean(axis=0)
    den = np.sqrt((a * a).sum() * (b * b).sum())
    return float((a * b).sum() / den) if den > 1e-12 else 0.0

def flash_score(sample_t_ms, sample_rgb, seq, t0_ms, cfg) -> FlashResult:
    """sample_t_ms: frame capture times (rVFC), sample_rgb: (T,3) mean skin-ROI RGB,
    seq: server-issued [(rgb 0..1, dur_ms)], t0_ms: paint time of segment 0 (same clock)."""
    f = cfg["flash"]
    t = np.asarray(sample_t_ms, float)
    obs = _chroma(np.asarray(sample_rgb, float))
    amplitude = float(obs.std(axis=0).max())
    best_ncc, best_lag, best_n = -1.0, 0.0, 0
    for lag in np.arange(0, f["max_search_lag_ms"] + 1, f["lag_step_ms"]):
        exp, ok = _expected(t - lag, seq, t0_ms, f["settle_ms"])
        if ok.sum() < f["min_samples"]:
            continue
        e = _chroma(exp[ok] + 1e-6)
        if len({tuple(np.round(x, 3)) for x in e}) < 2:    # need >= 2 distinct colours covered
            continue
        c = _ncc(obs[ok], e)
        if c > best_ncc:
            best_ncc, best_lag, best_n = c, float(lag), int(ok.sum())
    if best_n == 0:
        return FlashResult("unsure", 0.0, 0.0, amplitude, 0, "FLASH_TOO_FEW_SAMPLES")
    if amplitude < f["amplitude_min"]:
        return FlashResult("unsure", best_ncc, best_lag, amplitude, best_n, "FLASH_WEAK_SIGNAL")
    if best_ncc <= f["lo"]:
        return FlashResult("fail", best_ncc, best_lag, amplitude, best_n, "FLASH_MISMATCH")
    if best_ncc >= f["hi"] and best_lag > f["max_lag_ms"]:
        return FlashResult("fail", best_ncc, best_lag, amplitude, best_n, "FLASH_LAG")
    if best_ncc >= f["hi"]:
        return FlashResult("pass", best_ncc, best_lag, amplitude, best_n, None)
    return FlashResult("unsure", best_ncc, best_lag, amplitude, best_n, "FLASH_UNSURE")

def series_consistent(client_t, client_rgb, server_t, server_rgb, tol: float) -> bool:
    """Cross-check the client ROI series against server-recomputed means on uploaded JPEGs."""
    ct = np.asarray(client_t, float); cr = _chroma(np.asarray(client_rgb, float))
    sr = _chroma(np.asarray(server_rgb, float))
    idx = [int(np.argmin(np.abs(ct - ts))) for ts in server_t]
    return float(np.abs(cr[idx] - sr).max()) <= tol
```
**As built (`edge/ml/flash.py` + `edge/policy/liveness.py`), this differs from the sketch.** `r` is the
edge-measured `r_frames` from the uploaded frames **only**. The client chroma series is untrusted, and it was noisy:
r_client 0.33–0.98 vs r_frames 0.86–0.99 on genuine attempts (dev data). The `FLASH_*` strings above are internal
sketch labels, **not reason codes**. The policy maps FAIL → `SPOOF_FLASH_MISMATCH` and UNSURE/WEAK →
`LIVENESS_UNSURE`. YAML keys: `liveness.flash.lag_min_frames` 0 / `lag_max_frames` 8 (the measured webcam pipeline
delay is 4–7 frames), `lag_max_std_frames` 1.5, `min_amplitude` 2.0, `pass_min_r` 0.70, `fail_max_r` 0.30. When
`lag_ms` is sent, the policy converts it with the measured fps. **`liveness.flash.enforce: false` (ADVISORY):** the zone
is reported as `ADVISORY_<zone>` and has no decision effect until the kiosk frame timing is re-validated.

Notes:
- **Calibrate the baseline lag first.** Real faces show a pipeline lag (display, then the camera, then rVFC). On our MacBook webcam it measured 4–7 frames, not the 1–3 assumed here. Measure it on the demo laptop.
- Starting values: `hi 0.70`, `lo 0.30`, `settle_ms 60`, `lag_step_ms 10`, `max_search_lag_ms 250`, `min_samples 12` (dense series) or 3 (key frames only, which is less reliable), and `amplitude_min` taken from the live-face distribution under room light (start around 0.01 on the chromaticity std).
- Unit tests (`edge/tests/test_flash.py`): a synthetic in-phase response gives pass; a constant (screen ignoring the flash) gives unsure or fail depending on amplitude; a shuffled sequence gives fail; a response shifted by 200 ms gives `FLASH_LAG`; a noise-only signal is never pass.

## R6. Browser: Face Landmarker, frame timing, ROI series, injection probe (TypeScript)

```ts
import { FaceLandmarker, FilesetResolver, type FaceLandmarkerResult } from "@mediapipe/tasks-vision";

export async function createLandmarker(): Promise<FaceLandmarker> {
  const fileset = await FilesetResolver.forVisionTasks("/mediapipe/wasm"); // self-hosted for offline
  return FaceLandmarker.createFromOptions(fileset, {
    baseOptions: { modelAssetPath: "/models/face_landmarker.task", delegate: "GPU" },
    runningMode: "VIDEO", numFaces: 1,
    outputFaceBlendshapes: true, outputFacialTransformationMatrixes: true,
  });
}

export function blend(res: FaceLandmarkerResult): Record<string, number> {
  const out: Record<string, number> = {};
  for (const c of res.faceBlendshapes?.[0]?.categories ?? []) out[c.categoryName] = c.score;
  return out;
}

/** Euler angles (deg) from the column-major 4x4 matrix. Verify signs by turning your head. */
export function headPose(res: FaceLandmarkerResult) {
  const d = res.facialTransformationMatrixes?.[0]?.data;
  if (!d) return null;
  const R = (r: number, c: number) => d[c * 4 + r];
  const deg = 180 / Math.PI;
  return {
    pitch: Math.atan2(R(2, 1), R(2, 2)) * deg,
    yaw: Math.atan2(-R(2, 0), Math.hypot(R(2, 1), R(2, 2))) * deg,
    roll: Math.atan2(R(1, 0), R(0, 0)) * deg,
  };
}

const L_EYE = [362, 385, 387, 263, 373, 380], R_EYE = [33, 160, 158, 133, 153, 144];
export function ear(lm: { x: number; y: number }[], idx: number[]): number {
  const p = idx.map((i) => lm[i]);
  const dist = (a: typeof p[0], b: typeof p[0]) => Math.hypot(a.x - b.x, a.y - b.y);
  return (dist(p[1], p[5]) + dist(p[2], p[4])) / (2 * dist(p[0], p[3]) + 1e-6);
}

/** Per-frame loop using requestVideoFrameCallback (capture-accurate timestamps). */
export function runFrameLoop(video: HTMLVideoElement, lmk: FaceLandmarker,
                             onFrame: (t: number, res: FaceLandmarkerResult, meta: VideoFrameCallbackMetadata) => void) {
  const step = (_now: number, meta: VideoFrameCallbackMetadata) => {
    const t = meta.captureTime ?? meta.expectedDisplayTime;
    onFrame(t, lmk.detectForVideo(video, t), meta);
    video.requestVideoFrameCallback(step);
  };
  video.requestVideoFrameCallback(step);
}

/** Mean RGB over cheek/forehead ROI: draw the UNMIRRORED frame to a small canvas. */
export function roiMean(ctx: CanvasRenderingContext2D, video: HTMLVideoElement,
                        lm: { x: number; y: number }[], roiIdx: number[]): [number, number, number] {
  const W = ctx.canvas.width, H = ctx.canvas.height;
  ctx.drawImage(video, 0, 0, W, H);
  const xs = roiIdx.map((i) => lm[i].x * W), ys = roiIdx.map((i) => lm[i].y * H);
  const x0 = Math.max(0, Math.min(...xs) | 0), y0 = Math.max(0, Math.min(...ys) | 0);
  const w = Math.max(1, (Math.max(...xs) - x0) | 0), h = Math.max(1, (Math.max(...ys) - y0) | 0);
  const px = ctx.getImageData(x0, y0, w, h).data;
  let r = 0, g = 0, b = 0;
  for (let i = 0; i < px.length; i += 4) { r += px[i]; g += px[i + 1]; b += px[i + 2]; }
  const n = px.length / 4; return [r / n, g / n, b / n];
}

const VIRTUAL_RE = /obs|virtual|manycam|droidcam|snap camera|xsplit|splitcam|e2esoft|camtwist|iriun|epoccam|ndi|mmhmm|youcam/i;
export async function injectionProbe(stream: MediaStream, allowList: string[]) {
  const track = stream.getVideoTracks()[0];
  const s = track.getSettings();
  const devices = await navigator.mediaDevices.enumerateDevices();
  const dev = devices.find((d) => d.deviceId === s.deviceId);
  const label = dev?.label ?? track.label;
  return {
    device_label: label, device_id: s.deviceId ?? "",
    virtual_cam: VIRTUAL_RE.test(label),
    allow_listed: allowList.length === 0 || allowList.includes(label),
    fps: s.frameRate ?? null, width: s.width ?? null, height: s.height ?? null,
  };
}

export function jitterStats(ts: number[]) {
  const d = ts.slice(1).map((t, i) => t - ts[i]);
  const mean = d.reduce((a, b) => a + b, 0) / Math.max(1, d.length);
  const sd = Math.sqrt(d.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(1, d.length));
  return { frame_intervals_ms: d, mean_ms: mean, jitter_ms: sd, dup_frames: d.filter((x) => x < 1).length };
}
```
Flash overlay: a fixed `div` with `inset:0`, `transition: background-color 40ms ease`. Set the colour inside
`requestAnimationFrame` and record `performance.now()` as the paint time, on the same clock as the rVFC
times. Try `track.applyConstraints({ advanced: [{ exposureMode: "manual" } as any, { whiteBalanceMode: "manual" } as any] })`
only if `track.getCapabilities()` lists those modes.

## R7. Local matcher + Fernet-encrypted templates

```python
import json, numpy as np
from cryptography.fernet import Fernet

class TemplateStore:
    def __init__(self, key: bytes, model_id: str):
        self.f, self.model_id = Fernet(key), model_id
        self.ids: list[str] = []; self.T = np.zeros((0, 512), np.float32)

    def encrypt_user(self, user_id: str, embs: np.ndarray) -> bytes:
        payload = {"user_id": user_id, "model": self.model_id, "dim": int(embs.shape[1]),
                   "embs": embs.astype(np.float32).tobytes().hex()}
        return self.f.encrypt(json.dumps(payload).encode())

    def load(self, blobs: list[bytes]) -> None:
        ids, rows = [], []
        for b in blobs:
            p = json.loads(self.f.decrypt(b))
            if p["model"] != self.model_id:
                raise ValueError("template model mismatch")      # never mix embedding models
            e = np.frombuffer(bytes.fromhex(p["embs"]), np.float32).reshape(-1, p["dim"])
            ids += [p["user_id"]] * len(e); rows.append(e)
        self.ids, self.T = ids, (np.vstack(rows) if rows else self.T)

    def search(self, q: np.ndarray, cfg) -> dict:
        q = q / (np.linalg.norm(q) + 1e-9)
        s = self.T @ q
        best: dict[str, float] = {}
        for uid, sc in zip(self.ids, s):                          # max over each user's templates
            best[uid] = max(best.get(uid, -1.0), float(sc))
        ranked = sorted(best.items(), key=lambda kv: kv[1], reverse=True)
        if not ranked:
            return {"status": "no_match", "reason": "NOT_ENROLLED"}
        (u1, s1), s2 = ranked[0], (ranked[1][1] if len(ranked) > 1 else -1.0)
        m = cfg["match"]
        if s1 <= m["lo"]:
            status = "no_match"
        elif s1 >= m["hi"] and (s1 - s2) >= m["margin_min"]:
            status = "match"
        else:
            status = "unsure"
        return {"status": status, "top1_id": u1, "top1": s1, "top2": s2, "margin": s1 - s2}

def enrol_check(embs: np.ndarray, min_pair: float) -> bool:
    e = embs / np.linalg.norm(embs, axis=1, keepdims=True)
    S = e @ e.T
    return float(S[np.triu_indices(len(e), 1)].min()) >= min_pair
```
Get the embedding from uniface's recogniser, or from a raw ArcFace ONNX: RGB 112×112, `(x-127.5)/127.5`,
NCHW. Generate the key with `Fernet.generate_key()`, store it in `.env` as `TEMPLATE_KEY`, and never commit it.

Calibration helper (eval/):
```python
def calibrate(genuine: np.ndarray, impostor: np.ndarray, far_target: float = 0.002) -> dict:
    hi = max(float(np.quantile(impostor, 1 - far_target)), float(impostor.max()) + 0.02)
    lo = float(np.quantile(impostor, 0.90))
    frr = float((genuine < hi).mean())
    return {"hi": hi, "lo": lo, "frr_at_hi": frr, "n_gen": len(genuine), "n_imp": len(impostor),
            "note": "percentile unreliable if n_imp < 3/far_target"}
```

## R8. Rekognition user vectors (boto3, sandbox us-east-1; production ap-south-1)

As built: `cloud/app/services/faces.py` (AWS adapter, error mapping) + `match_service.py`. The sketch shows the call
shapes. The region comes from `CLOUD_AWS_REGION` (the cloud app deliberately ignores `AWS_REGION`; sandbox = **us-east-1**; production would pin
**ap-south-1** for data residency). Consenting team faces only; the collection is deleted at teardown.

```python
import os, uuid, boto3
from botocore.config import Config

rk = boto3.client("rekognition", region_name=os.environ.get("CLOUD_AWS_REGION", "us-east-1"),
                  config=Config(retries={"mode": "adaptive", "max_attempts": 2},
                                connect_timeout=0.5, read_timeout=1.0))
COLL = os.environ.get("REKOGNITION_COLLECTION_ID", "hid-kiosk-users")

def enrol_user(user_id: str, jpegs: list[bytes]) -> list[str]:
    face_ids = []
    for jpg in jpegs:
        r = rk.index_faces(CollectionId=COLL, Image={"Bytes": jpg}, ExternalImageId=user_id,
                           MaxFaces=1, QualityFilter="HIGH", DetectionAttributes=[])
        face_ids += [fr["Face"]["FaceId"] for fr in r["FaceRecords"]]
    try:
        rk.create_user(CollectionId=COLL, UserId=user_id, ClientRequestToken=str(uuid.uuid4()))
    except rk.exceptions.ConflictException:
        pass                                                   # user already exists
    if face_ids:
        rk.associate_faces(CollectionId=COLL, UserId=user_id, FaceIds=face_ids,
                           UserMatchThreshold=80, ClientRequestToken=str(uuid.uuid4()))
    return face_ids

def search_user(jpg: bytes, R) -> dict:
    """R = thresholds match.rekognition. Returns raw scores; the EDGE policy assigns the zone."""
    r = rk.search_users_by_image(CollectionId=COLL, Image={"Bytes": jpg}, MaxUsers=2,
                                 UserMatchThreshold=R.user_match_threshold, QualityFilter=R.quality_filter)
    m = r.get("UserMatches", [])
    return {"user_id": m[0]["User"]["UserId"] if m else None,
            "similarity": m[0]["Similarity"] if m else None,
            "runner_up_similarity": m[1]["Similarity"] if len(m) > 1 else None}
```
Any AWS error, throttle or timeout → the cloud answers `503` (e.g. `UPSTREAM_THROTTLED`), and the edge treats the
match as failed: the **whole attempt becomes OFFLINE** (P7) and a connectivity miss is recorded. There is no
"DEGRADED" mode or code. Zones (edge, `edge/policy/identity.py`, `match.rekognition`): PASS = similarity ≥
`allow_min_similarity` (99) and runner-up < `runner_up_max_similarity` (80); [80, 99) → `MATCH_LOW`; runner-up ≥ 80 →
`MATCH_AMBIGUOUS`; no match or < `deny_below_similarity` (80) → `NOT_ENROLLED`. The local cross-check uses
`identity.cross_check_conflict_min_cosine` (0.50). With `match.rekognition.enabled: false`, the edge uses the local
matcher with the offline bars. Design for the Mumbai default quotas (5 TPS Search/Index/Associate) even in us-east-1.

## R9. Depth checks (DepthProbe frames)

As built: `depth/checks.py` `compute_depth_checks(depth, *, depth_type, intrinsics, face_box_norm, landmarks_norm, cfg,
template=None, accuracy=None)`, `compute_m1(...)`, `make_template(...)`; the edge calls it through
`edge/depth_bridge.py` when `POST /v1/depth/frames` arrives. Input = 1–3 synchronised TrueDepth frames from the
**DepthProbe** app (`depth_type` disparity or depth, `float16`/`float32`, intrinsics, `accuracy` absolute|relative,
face box + landmarks normalised to [0, 1] in the depth buffer's orientation). Stacks are fused with a per-pixel
median. The minimal numpy core (illustrative):

```python
import numpy as np

def backproject(depth_m: np.ndarray, K: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """depth in metres -> Nx3 points in mm for pixels in mask with valid depth."""
    v, u = np.nonzero(mask & np.isfinite(depth_m) & (depth_m > 0))
    z = depth_m[v, u] * 1000.0
    fx, fy, cx, cy = K[0, 0], K[1, 1], K[0, 2], K[1, 2]
    return np.column_stack([(u - cx) * z / fx, (v - cy) * z / fy, z])

def valid_ratio(depth_m, mask) -> float:                       # D0
    d = depth_m[mask]; return float((np.isfinite(d) & (d > 0)).mean()) if d.size else 0.0

def plane_rms(P: np.ndarray, iters: int = 50, inlier_mm: float = 4.0, seed: int = 0) -> float:  # D1
    rng = np.random.default_rng(seed)                           # deterministic for tests
    best = P
    for _ in range(iters):                                      # light RANSAC to drop hair/background
        s = P[rng.choice(len(P), 3, replace=False)]
        n = np.cross(s[1] - s[0], s[2] - s[0]); nn = np.linalg.norm(n)
        if nn < 1e-9: continue
        d = np.abs((P - s[0]) @ (n / nn))
        inl = P[d < inlier_mm * 3]
        if len(inl) > len(best) * 0.9 or best is P: best = inl
    c = best.mean(axis=0)
    _, _, Vt = np.linalg.svd(best - c, full_matrices=False)     # normal = smallest singular vector
    resid = (best - c) @ Vt[2]
    return float(np.sqrt(np.mean(resid ** 2)))

def quad_rms(P: np.ndarray) -> float:                           # D2: z = f(x, y), degree 2
    x, y, z = P[:, 0], P[:, 1], P[:, 2]
    A = np.column_stack([np.ones_like(x), x, y, x * x, x * y, y * y])
    coef, *_ = np.linalg.lstsq(A, z, rcond=None)
    return float(np.sqrt(np.mean((z - A @ coef) ** 2)))

def nose_relief(depth_m, nose_uv, cheek_uvs, r: int = 3) -> float:   # D3 (mm)
    patch = lambda u, v: np.nanmedian(np.where(depth_m[v-r:v+r+1, u-r:u+r+1] > 0,
                                               depth_m[v-r:v+r+1, u-r:u+r+1], np.nan))
    cheeks = np.nanmedian([patch(u, v) for u, v in cheek_uvs])
    return float((cheeks - patch(*nose_uv)) * 1000.0)
```

DepthProbe sends the face box and landmarks with the frames. When it does not, the edge runs its own detector on the
JPEG part. RGB and depth share the field of view, so normalised coordinates carry over. D4 (metric IPD) runs only
with `accuracy == "absolute"` (`require_absolute_depth_for_d4`). Report `{D0, D1_rms, D2_rms, D3_mm, D4_ipd_mm|None,
M1.., latency_ms}`; `None` means "not measured" and never counts as a pass. Depth is used only when
`liveness.depth.enabled: true`, which waits for the H4 calibration (`python -m depth.calibrate`, ≥ 10 live + ≥ 10
printed photos). Test on a printed photo before claiming anything.

## R10. Policy engine skeleton (pure)

As built: `edge/policy/engine.py` (`evaluate`, `combine`, `biometric_result`), wrapped by `edge/policy/runtime.py`
(clock, demo clock, sessions, rate limiter, persistence). The sketch shows the **stage order and canonical codes
only**. Every code is from the closed list in `edge/policy/codes.py`; never invent one. HTTP-level problems (bad
nonce, closed attempt) are API errors (`NONCE_INVALID` → 403 `FORBIDDEN`, `NONCE_EXPIRED` 410, `NONCE_REUSED` 409),
**not** reason codes.

```python
from edge.policy.codes import HARD_SPOOF_CODES, dedupe   # closed list, deterministic order

ALLOW, STEP_UP, DENY = "ALLOW", "STEP_UP", "DENY"

def evaluate(sig, ctx, mode, now, T, rng) -> "Decision":
    try:
        return _evaluate(sig, ctx, mode, now, T, rng)
    except Exception:                       # unknown enum, missing field, model crash, ...
        return system_error(sig, ctx, mode, now)   # DENY [SYSTEM_ERROR], logged; never HTTP 500, never ALLOW

def _evaluate(sig, ctx, mode, now, T, rng):
    # 0. rate limit (attack-evidence DENYs only, rate_limit.*)
    if ctx.rate_limited:
        return deny(["RATE_LIMITED"], next_action="NONE")             # + retry_after_s
    # 1. quality: QUALITY_LOW_LIGHT / QUALITY_BLUR / QUALITY_POSE / MULTIPLE_FACES / QUALITY_DEPTH_INVALID
    q = quality(sig, T.quality)
    if not q.ok:
        if sig.recapture_count < T.quality.max_recaptures:
            return step_up(q.codes, "RECAPTURE")
        if injection(sig, T) == "FAIL":                              # injection still runs first (A4)
            return deny(["INJECTION_VIRTUAL_CAMERA"])
        if high_risk(ctx.zone_risk, mode, T):
            return deny(q.codes, next_action="CONTACT_DESK")
        return step_up(q.codes + (["OFFLINE_FALLBACK_REQUIRED"] if mode == "OFFLINE" else []),
                       "SECOND_FACTOR", methods=T.stepup.methods.quality_exhausted)   # staff review
    # 2. injection
    if injection(sig, T) == "FAIL":
        return deny(["INJECTION_VIRTUAL_CAMERA"])
    # P7: online + Rekognition enabled + cloud match failed -> whole attempt OFFLINE
    # 3 + 4. liveness fusion (SPOOF_*, MASK_CUE_*, LIVENESS_UNSURE) || identity (MATCH_LOW / MATCH_AMBIGUOUS / NOT_ENROLLED)
    live, ident = liveness_fusion(sig, T, mode), identity_match(sig, T, mode)
    # 5. biometric result: hard spoof or >= strong_cue_deny_count strong mask cues -> BIO_FAIL (DENY).
    #    On BIO_FAIL only the failing codes are returned: no unsure codes and NO SCHEDULE_* codes.
    bio, codes = biometric_result(live, ident, T.liveness.mask.strong_cue_deny_count)
    if bio == "BIO_FAIL":
        return deny(codes, next_action="CONTACT_DESK" if codes == ["NOT_ENROLLED"] else "NONE")
    # 6. SC1 schedule: only for BIO_PASS / BIO_UNSURE, on the last valid bundle (no LVB -> DENY SCHEDULE_BUNDLE_INVALID)
    sched = evaluate_schedule(ident.user_id, ctx.zone, sig.t0, ctx.bundle, T.schedule)   # or None if INVALID
    # 7. SC2 mode restrictions + 8. final decision (OFFLINE_MODE, OFFLINE_HIGH_RISK_ZONE, OFFLINE_FALLBACK_REQUIRED,
    #    SCHEDULE_EXPIRED_CACHE, SCHEDULE_BUNDLE_INVALID, SCHEDULE_HIGH_RISK_ZONE online); each stage keeps or tightens.
    out = combine(bio, codes, sched, ctx.cache_state, ctx.zone_risk, mode, T)
    # optional random challenge: one draw, only on a would-be ALLOW (challenge.random_rate, 0.0 by default)
    if out.decision == ALLOW and rng.random() < T.challenge.random_rate:
        out = step_up(["RANDOM_CHALLENGE"] + (["OFFLINE_MODE"] if mode == "OFFLINE" else []), "CHALLENGE")
    return out                              # ALLOW carries ACCESS_OK; step-up triggers move to resolved_codes
```
The tests in `docs/POLICY_TEST_CASES.md` (implemented in `edge/policy/tests/test_cases.py`) are the spec.

Schedule evaluator core:
```python
from datetime import datetime, time
from zoneinfo import ZoneInfo
IST = ZoneInfo("Asia/Kolkata")

def in_window(now_ist: datetime, start: time, end: time) -> bool:
    t = now_ist.timetz().replace(tzinfo=None)
    return start <= t < end if start <= end else (t >= start or t < end)   # midnight-spanning
```
Revocation is time-aware (`revoked_at` ≤ t0) and is checked first (REVOKED → NO_ENTITLEMENT → ZONE_NOT_PERMITTED →
HOLIDAY → IN_WINDOW → GRACE_WINDOW → OUTSIDE_WINDOW).

## R11. Offline: bundle signature, TOTP fallback, hash chain, sync

As built: `edge/offline/bundle.py`, `edge/offline/store.py`, `edge/offline/sync.py`, `edge/policy/fallback.py`.

```python
import hashlib, hmac, json, pyotp

def canon(obj) -> bytes:                               # canonical JSON (bundle, chain, sync items)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def bundle_sig(bundle: dict, key: bytes) -> str:       # HMAC-SHA256 over the bundle minus "signature"
    return hmac.new(key, canon({k: v for k, v in bundle.items() if k != "signature"}), hashlib.sha256).hexdigest()

def verify_bundle(bundle: dict, key: bytes) -> bool:   # key = SCHEDULE_BUNDLE_HMAC_KEY
    # as built: edge/offline/bundle.py verify_bundle(bundle, key, key_id) also pins signature.key_id
    # (SCHEDULE_BUNDLE_KEY_ID, default "demo-k1"); a rotated-out key id is refused
    sig = bundle.get("signature") or {}
    return sig.get("alg") == "HMAC-SHA256" and isinstance(sig.get("value"), str) \
        and hmac.compare_digest(sig["value"], bundle_sig(bundle, key))      # constant-time compare

def totp_ok(secret_b32: str, code: str, real_now) -> bool:   # real wall time, never the demo clock
    # as built: edge/policy/fallback.py totp_matching_step() also returns the matched step (replay check, totp_step)
    return pyotp.TOTP(secret_b32).verify(code, for_time=real_now, valid_window=1)

def genesis(kiosk_id: str) -> str:
    return hashlib.sha256(f"genesis:{kiosk_id}".encode()).hexdigest()

def record_hash(prev_hash: str, record: dict) -> str:
    body = {k: v for k, v in record.items() if k not in ("prev_hash", "record_hash")}
    return hashlib.sha256(prev_hash.encode("ascii") + canon(body)).hexdigest()
```
- **Signature:** hackathon = HMAC-SHA256 with `SCHEDULE_BUNDLE_HMAC_KEY`, `signature = {alg, key_id, value}`.
  **Ed25519 is the production roadmap only** (the kiosk would hold just the public key). Never KMS/ECDSA.
- **Signer** (`scripts/sign_bundle.py`, source `config/schedule.demo.json`; the cloud for refreshes) stamps
  `issued_at` = now, `expires_at` = now + 12 h, and each override code's `valid_until` = `expires_at` +
  `fallback.staff_override.valid_after_expiry_h` (24 h).
- **Last valid bundle (LVB):** a received bundle that fails verification, does not cover the kiosk or is older is
  rejected with an alert and never replaces the LVB. A file tampered on disk is rejected and the in-memory LVB stays.
  INVALID only when there is no LVB or the clock rolled back (now < `issued_at` − `cache.clock_rollback_tolerance_s`).
- **Decision log** (one record per attempt, SC2.5 fields only, AES-256-GCM payload, 2 dp scores; `fallback =
  {method, staff_id, code_id, totp_step}`, where `totp_step` is not secret and lets the cloud spot cross-kiosk TOTP replay
  (Y07)). Purge on ack; unsynced records purged after `offline_store.max_retention_hours` (24 h), leaving a tombstone
  `{count, first_seq, last_seq, chain_head}`.
- **Sync** (`docs/API.md` v1.1 §4.4): `POST /v1/sync` with
  `{kiosk_id, batch_id: "b_<ULID>", kiosk_now_utc, chain_head, chain_head_hmac, items: [≤ sync.batch_size (50)]}`.
  Items = the SC2.5 record + `idempotency_key` (= `attempt_id`) + `hmac`, or `{type: "TOMBSTONE", count, first_seq,
  last_seq, chain_head, hmac}`. `chain_head` = `record_hash` of the last record in the batch; `chain_head_hmac` =
  HMAC(kiosk key, chain_head). Response `{accepted[], duplicates[], rejected[], flags[], server_time}`: delete the
  accepted and duplicate records, retry the rest with backoff `backoff_initial_s` 1 → `backoff_max_s` 60 s, ±20 %
  jitter. There is no `/v1/sync/decisions`, no 100-record batch and no `Idempotency-Key` header.

## R12. Latency: concurrent stages, timers, warm-up

As built: `edge/attempts.py` (`liveness_branch` ‖ `match_branch` via `asyncio.gather` on a thread pool),
`edge/metrics.py`; warm-up and the MiniFASNet self-test in the FastAPI lifespan (`edge/app.py`).

```python
import asyncio, time
from contextlib import contextmanager

@contextmanager
def timed(lat: dict, name: str):
    t = time.perf_counter()
    try: yield
    finally: lat[name] = round((time.perf_counter() - t) * 1000, 1)

async def process_frames(ctx, att, jpegs, meta):   # simplified; real: edge/attempts.py
    ts = meta.frame_timestamps_ms
    lat: dict[str, float] = {}
    t0 = time.perf_counter()
    try:
        with timed(lat, "quality"):
            analysed = await analyze_jpegs(ctx, jpegs, ts)          # decode, detect, align, quality
        live, match = await asyncio.gather(
            liveness_branch(ctx, att, meta, analysed), match_branch(ctx, att, analysed, jpegs))  # + depth_branch; cloud match time-boxed
        with timed(lat, "policy"):
            decision = ctx.runtime.decide(build_signals(att, analysed, live, match), lat)
    except Exception:                                              # any stage crash: fail secure
        decision = ctx.runtime.decide_error(att.attempt_id, detail="perception stage failed")   # DENY SYSTEM_ERROR
    lat["total"] = round((time.perf_counter() - t0) * 1000, 1)
    return decision, lat
```
There are no `STAGE_ERROR_*` codes. A crash or an invalid input in any stage gives `DENY` + `SYSTEM_ERROR`
(logged, never HTTP 500), and a missing *optional* signal (depth, flash on the non-flash path) is `NOT_AVAILABLE`,
never a pass. The cloud match has its own time box (`latency_budget_ms.rekognition_timeout`, 700 ms). Exceeding it
makes the attempt OFFLINE (P7), not "unsure". The thread pool works because onnxruntime and OpenCV release the GIL. Use
2 intra-op threads per session. Log `lat` with `policy_version` for every attempt so that eval/ can compute p50 and
p95 for each stage. Dev measurement (n = 32, offline, MacBook webcam): edge server total p50 127 ms / p95 154 ms.
