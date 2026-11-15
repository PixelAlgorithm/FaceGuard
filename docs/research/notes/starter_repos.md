> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# Starter GitHub repos for the liveness + face-auth kiosk

Checked on 2026-11-14. Every repo listed under a category heading was fetched through the authenticated GitHub API (`gh api repos/...`), and its README and/or file tree was read. Stars, `pushed_at`, license and language come straight from the API. "none" means the API reports no license, so the code is all-rights-reserved: you can read it for reference, but don't copy it wholesale.

Plan context: `basic_idea.txt`. The stack is a React kiosk with MediaPipe Face Landmarker, a FastAPI backend, MiniFASNet ONNX, Rekognition plus InsightFace, and the colour flash, all in ap-south-1.

Effort scale: **S** = under 1 h to get running and wired in, **M** = 1-3 h, **L** = more than 3 h, or only useful as reference.

---

## 1. Passive anti-spoofing with weights (MiniFASNet)

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [yakhyo/face-anti-spoofing](https://github.com/yakhyo/face-anti-spoofing) | 50 | 2026-10-20 | Apache-2.0 | Python |
| [facenox/face-antispoof-onnx](https://github.com/facenox/face-antispoof-onnx) | 277 | 2026-10-15 | Apache-2.0 | Python |
| [minivision-ai/Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing) | 1848 | 2023-10-03 | Apache-2.0 | Python |
| [QingHeYang/Silent-Face-Anti-Spoofing-onnx](https://github.com/QingHeYang/Silent-Face-Anti-Spoofing-onnx) | 15 | 2025-10-13 | Apache-2.0 | Python |

- **yakhyo/face-anti-spoofing**: a minimal PyTorch and ONNX Runtime inference repo for MiniFASNetV2 (crop scale 2.7) and MiniFASNetV1SE (crop scale 4.0). **Verified:** the release `weights` has `MiniFASNetV2.onnx`, `MiniFASNetV1SE.onnx` and the `.pth` files. It includes `onnx_inference.py` and `onnx_export.py`. **Effort: S.** Copy the ONNX inference function into FastAPI and run both models (the original 2-model ensemble). **Gotcha:** you have to reproduce the bbox scale crop exactly (2.7 / 4.0, then 80x80), or the scores are meaningless. The README says it's now folded into `uniface` (see section 6).
- **facenox/face-antispoof-onnx**: a retrained MiniFASNetV2-SE, 128x128 input, 1.82 MB, or 600 KB INT8 quantized. The README reports 98.2% accuracy and 0.9984 ROC-AUC on CelebA-Spoof. **Verified:** `models/best_model_quantized.onnx` (626 KB) is in the repo, along with a small `detector.onnx`. **Effort: S.** It's a good *second opinion* model to fuse with the minivision pair. **Gotchas:** it was trained and evaluated on CelebA-Spoof, which is non-commercial research data (the same caveat as InsightFace; mention it in the pitch). It uses a different input size and preprocessing from the original MiniFASNet.
- **minivision-ai/Silent-Face-Anti-Spoofing**: the original upstream. **Verified:** `resources/anti_spoof_models/2.7_80x80_MiniFASNetV2.pth` and `4_0_0_80x80_MiniFASNetV1SE.pth` are there (about 1.8 MB each). It also has training code if anyone wants to fine-tune on our own captures. **Effort: M** (PyTorch only, old code). **Gotcha:** no new commits since 2023. Use it as the reference for the crop logic (`src/generate_patches.py`).
- **QingHeYang/Silent-Face-Anti-Spoofing-onnx**: the same two models already converted to ONNX (`onnx/2.7_80x80_MiniFASNetV2.onnx`, `onnx/4_0_0_80x80_MiniFASNetV1SE.onnx`), with a test script and sample real and fake images. **Effort: S.** It's a fallback if the yakhyo release download is blocked. The sample images are handy for unit tests.

Also seen but not recommended: `zeusees/HyperFAS` (BSD-3, last push 2021), `hairymax/Face-AntiSpoofing` (no license), `SoftwareGift/FeatherNets` (CVPR2019, depth/IR dataset).

---

## 2. Full liveness + recognition pipelines (API / web app)

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [vadimgodev/face-recognition](https://github.com/vadimgodev/face-recognition) ("FaceGuard") | 5 | 2026-11-09 | MIT | Python |
| [openbm/openbiometrics](https://github.com/openbm/openbiometrics) | 11 | 2026-03-22 | MIT | Python |
| [amoghgg/face-biometrics-api](https://github.com/amoghgg/face-biometrics-api) | 4 | 2026-10-13 | MIT | Python |
| [WellCod/face-gate](https://github.com/WellCod/face-gate) | 5 | 2026-09-18 | MIT | Python |
| [watcharaponthod-code/ekyc](https://github.com/watcharaponthod-code/ekyc) | 0 | 2026-09-20 | **none** | JS/Python |

- **vadimgodev/face-recognition (FaceGuard)**: **closest to our backend.** It's FastAPI, InsightFace and Silent-Face MiniFASNet (the `src/antispoof/` module with `predictor.py` and `MiniFASNet.py`), with pgvector and Redis. It has a **"hybrid" mode in which local similarity at 0.8 or above is trusted, 0.6-0.8 is verified with AWS Rekognition `CompareFaces`, and anything below 0.6 is rejected.** That's almost exactly our two-threshold idea. It also has a door-unlock webhook trigger and a Vue 3 UI. **Effort: M.** Lift `src/antispoof/` and the hybrid-matching service, but skip the Traefik/Postgres/Redis deployment. **Gotchas:** tiny community (5 stars), the UI is Vue rather than React, and InsightFace weights are non-commercial.
- **openbm/openbiometrics**: a FastAPI engine with passive MiniFASNet, **active liveness presets** (`eye`, `smile`, head-turn, full) through `POST /api/v1/liveness/sessions?preset=smile`, FAISS watchlists, and a model tier system. Its defaults are commercial-safe (YuNet MIT, SFace Apache-2.0, MiniFASNet Apache-2.0), with InsightFace as an optional non-commercial "legacy" tier. **Effort: M.** It's a good reference for a session-based challenge API and for a commercially clean model set. **Gotcha:** the YOLOv8n person detector is AGPL-3.0.
- **amoghgg/face-biometrics-api**: FastAPI with InsightFace buffalo_l, MediaPipe FaceLandmarker (blendshapes) and FAISS. It offers **rPPG (CHROM) liveness over WebSocket**, a challenge WebSocket (look left / right / smile, 20 consecutive frames each), photo-quality gating, and simple FFT and noise-floor checks for AI-generated images. **Effort: M.** Borrow the quality gate, the blendshape challenge logic and the spectral-slope code (it's related to our FFT moire check). **Gotcha:** the frontend is React Native (Expo) plus vanilla JS, not React web.
- **WellCod/face-gate**: FastAPI with DeepFace ArcFace, MediaPipe FaceMesh blink EAR (with hysteresis, 0.21 / 0.25), SQLite and Docker. Small and readable, with a good audit-log pattern. **Effort: S** as reference only. Blink-only liveness is exactly what our plan rejects (eye-cut mask).
- **watcharaponthod-code/ekyc**: React Native plus FastAPI (MediaPipe, DeepFace ArcFace, MiniFASNet ensemble). It includes **`server/app/flash.py` (server-issued random colour flash, per-channel Pearson correlation)**, an `openMouth` challenge against masks, rPPG, and an ISO/IEC 30107-3 APCER/BPCER harness (`docs/pad-evaluation.md`). Conceptually it's the closest match to our *whole* plan. **Gotcha: there's no LICENSE file**, so read it and reimplement; don't copy it. The author says it has never run on a physical phone.

Also verified, lower priority: `intikhab49/secureface-liveness-detection` (InsightFace, ChromaDB, two-layer liveness, no license), `Rollingcat-Software/biometric-processor` (a heavy FastAPI clean-architecture service with a "puzzle liveness session" anti-replay design, MIT), `asalazarvaldiviaocg/biometrical-verify` (ID plus selfie plus liveness, MIT), `facenox/facenox` (AGPL-3.0, so avoid), and `Faceplugin-ltd/Open-Source-Face-Recognition-SDK` (3.1k stars, no license, a vendor SDK teaser).

---

## 3. Active liveness in the browser

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [google-ai-edge/mediapipe-samples](https://github.com/google-ai-edge/mediapipe-samples) | 2888 | 2026-11-12 | Apache-2.0 | JS/TS etc. |
| [vladmandic/human](https://github.com/vladmandic/human) | 3384 | 2025-12-13 | MIT | JS |
| [sinterwong/liveness-detection-demo](https://github.com/sinterwong/liveness-detection-demo) | 19 | 2026-06-08 | none | JS |
| [icurtis1/mediapipe-face-tracking](https://github.com/icurtis1/mediapipe-face-tracking) | 48 | 2025-05-11 | none | TS |
| [aws-samples/liveness-detection](https://github.com/aws-samples/liveness-detection) | 105 | 2023-04-26 | MIT-0 | TS |

- **google-ai-edge/mediapipe-samples** `examples/face_landmarker/js`: the official Face Landmarker web sample (478 landmarks, **52 blendshapes** such as `mouthSmileLeft`, `jawOpen`, `cheekPuff` and `eyeBlinkLeft`, plus the facial transformation matrix for head pose). **Effort: S.** Port it into a React `useEffect` hook. Its blendshapes cover our smile, open-mouth and cheek-puff step-up directly. This is the canonical source to build from.
- **vladmandic/human** `demo/faceid`: **verified** that the demo exists. It runs a browser-side validation loop: face count, size, gaze direction, **blink with a temporal blink-speed check**, the optional `antispoof` model (`models/antispoof.json`) and the optional `liveness` model (`models/liveness.json`), then matches against IndexedDB. **Effort: M.** Use it as a client-side pre-filter or as a reference for the gating state machine. **Gotchas:** it's built on TF.js rather than MediaPipe tasks, so it's a second runtime. The author describes antispoof and liveness as tiny (under 1 MB), "quick check" models. The sibling `vladmandic/face-api` is **archived**.
- **sinterwong/liveness-detection-demo**: a pure front-end MediaPipe landmarker challenge demo (nod, shake, open mouth, blink), with a live GitHub Pages demo. **Effort: S** for lifting the thresholds. No license, so reimplement. The README is in Chinese.
- **icurtis1/mediapipe-face-tracking**: a React 18, TypeScript, Vite and Tailwind webcam scaffold. **Gotcha:** it uses the legacy `@mediapipe/face_mesh` and `camera_utils` (`tasks-vision` is listed but the README describes Face Mesh). It's useful only as a React or Vite webcam shell. No license.
- **aws-samples/liveness-detection**: AWS's older custom challenge ("move your nose to a random target and rotate your face"), built with face-api.js and a SAM backend that verifies on the server. **Effort: L.** It's a reference for the server-side challenge-state design. Its own README now points to Rekognition Face Liveness instead.

Also seen: `justadudewhohacks/face-api.js` (18k stars, MIT, last push 2024-01, effectively unmaintained) and `Faceplugin-ltd/FaceRecognition-LivenessDetection-Javascript` (an npm SDK marketed as "iBeta L2"; vendor, not truly open).

---

## 4. AWS: Rekognition Face Liveness, face search, user vectors

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [aws-amplify/amplify-ui](https://github.com/aws-amplify/amplify-ui) (`packages/react-liveness`) | 1144 | 2026-11-14 | Apache-2.0 | TS |
| [aws-samples/amazon-rekognition-face-liveness-demo](https://github.com/aws-samples/amazon-rekognition-face-liveness-demo) | 30 | 2024-02-23 | MIT-0 | Python (CDK) + React |
| [aws-samples/online-identity-verification](https://github.com/aws-samples/online-identity-verification) | 16 | 2026-07-22 | MIT-0 | Python (CDK) |
| [aws-samples/rekognition-user-vectors](https://github.com/aws-samples/rekognition-user-vectors) | 5 | 2024-04-25 | MIT-0 | Notebook/Python |
| [aws-samples/rekognition-identity-verification](https://github.com/aws-samples/rekognition-identity-verification) | 48 | 2023-09-21 | MIT-0 | Python (CDK) |

- **amplify-ui `@aws-amplify/ui-react-liveness`**: **verified** that `packages/react-liveness` (v3.7.0) exports `FaceLivenessDetector`. This is the drop-in React component for the step-up path. **Effort: M.** You need a Cognito identity pool (or a custom credentials provider) for the browser stream, plus a backend that calls `CreateFaceLivenessSession` and `GetFaceLivenessSessionResults`. Those two calls are easy to add to FastAPI with boto3. **Region:** AWS docs list `streaming-rekognition.ap-south-1.amazonaws.com`, so Face Liveness is available in Mumbai.
- **aws-samples/amazon-rekognition-face-liveness-demo**: a CDK stack (`one-click.sh`) plus a React Amplify frontend (`.env.local` with the API URL and Cognito IDs). **Effort: M-L.** It's the fastest path to a working Face Liveness demo if the sandbox allows CDK and Cognito. Otherwise copy just the session-create and result Lambdas into FastAPI. **Gotcha:** last push 2024-02, so expect dependency drift.
- **aws-samples/online-identity-verification**: newer (2026-07). It combines DetectFaces, CompareFaces and Face Liveness, with manual-CDK instructions and Python 3.13 notes. **Gotcha:** the README says the stack is "**only us-east-1**". Pull the code but call the APIs in ap-south-1 from our own backend.
- **aws-samples/rekognition-user-vectors**: **this is the SearchUsersByImage / user-vector example** (`detect_users.py`, `helpers.py`, notebook). It shows CreateCollection, IndexFaces, CreateUser, AssociateFaces and SearchUsersByImage. **Effort: S.** Lift `helpers.py` into the enrolment and auth endpoints. Enrol 3-5 images per teammate and associate them into one UserId.
- **aws-samples/rekognition-identity-verification (RIV)**: a full serverless register and auth flow (Step Functions in `infra/userportal/states/auth.py` and `register_user.py`, `search_faces_by_image`). **Effort: L.** It's mainly a reference for the register/auth state machine and DynamoDB layout. It uses the older face-level search, not user vectors.

Not found: `aws-samples/serverless-face-authentication`, `amazon-rekognition-serverless-face-liveness` and `amazon-rekognition-identity-verification` all return 404. `aws-samples/amazon-rekognition-virtual-proctor` and `amazon-rekognition-code-samples` are **archived**.

---

## 5. Colour-flash / screen-light reflection liveness

The pickings are slim. No well-starred open implementation exists (the commercial equivalents are iProov Flashmark and AWS Face Liveness).

| Repo | Stars | Pushed | License | Notes |
|---|---|---|---|---|
| [watcharaponthod-code/ekyc](https://github.com/watcharaponthod-code/ekyc) `server/app/flash.py`, `packages/react-native-ekyc/src/ui/flashColors.ts` | 0 | 2026-09-20 | **none** | Server-issued random sequence. The palette uses off-primaries (`red=(1,.15,.15)` and so on) so the face isn't left black, and scoring is the per-channel Pearson correlation of commanded vs observed mean face colour, with negatives clamped and `FLASH_MIN=0.5` and `FLASH_MIN_FRAMES=3`. It also has tests (`server/tests/test_flash.py`). **This is the best design reference, but there's no license, so reimplement it (about 60 lines of numpy).** |
| [VallabhiPatil/Face-Liveness-Detector](https://github.com/VallabhiPatil/Face-Liveness-Detector) | 3 | 2026-01-18 | none | A Flask "3step" app with MediaPipe and a "flash-based" check. The code is messy (numbered scripts and archives). Low value. |
| [david-zzy/Aurora-Guard-...-Light-Reflection](https://github.com/david-zzy/Aurora-Guard-Real-Time-Face-Anti-Spoofing-via-Light-Reflection) | 0 | 2020-09-23 | none | Only a placeholder for the Aurora Guard paper (light-reflection FAS). Cite the paper, not the repo. |

Our implementation plan is to write our own. The client renders the server-chosen colours full-screen and timestamps each frame. The server takes the mean RGB of the cheek and forehead ROI (from MediaPipe landmarks) per frame, applies a lag-tolerant (0-2 frame) per-channel correlation, and uses the plan's thresholds (0.7 to pass, 0.3 to fail). The ekyc code is a useful check on the math.

---

## 6. Face recognition libraries and vector search

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [yakhyo/uniface](https://github.com/yakhyo/uniface) | 2224 | 2026-11-12 | MIT (code) | Python |
| [deepinsight/insightface](https://github.com/deepinsight/insightface) | 30222 | 2026-10-19 | code MIT; **weights non-commercial** | Python |
| [serengil/deepface](https://github.com/serengil/deepface) | 23698 | 2026-11-13 | MIT | Python |
| [SthPhoenix/InsightFace-REST](https://github.com/SthPhoenix/InsightFace-REST) | 630 | 2025-06-01 | Apache-2.0 | Python |
| [ruhyadi/vision-fr](https://github.com/ruhyadi/vision-fr) | 7 | 2024-07-07 | none | Python |

- **yakhyo/uniface**: `pip install "uniface[cpu]"` gives one package with detection (RetinaFace/SCRFD), ArcFace / AdaFace / **AuraFace** / EdgeFace recognition, **MiniFASNet anti-spoofing**, **eDifFIQA face quality**, head pose, face states (glasses, mask), and a **FAISS vector store**. All of it is ONNX on CPU, and weights download on first use. **Effort: S.** This is probably the single highest-leverage library for the FastAPI backend: quality gate, anti-spoof and local match in one dependency. **Gotcha:** the README says "some pretrained weights are not [MIT]", so check its license-attribution page. Prefer AuraFace or EdgeFace if commercial-cleanliness matters.
- **deepinsight/insightface**: `FaceAnalysis(name="buffalo_l")` is the backup matcher in our plan. **Gotcha (verified in the README):** "training data ... and the models trained with these data are available for non-commercial research purposes only". That's fine for the hackathon, but state it.
- **serengil/deepface**: `DeepFace.extract_faces(..., anti_spoofing=True)` and `DeepFace.verify` / `find` (**verified** in the README). It wraps the minivision MiniFASNet and many recognizers (ArcFace, Facenet512, SFace, Buffalo_L). **Effort: S** as a sanity baseline or second matcher. **Gotchas:** it pulls TensorFlow, so it's heavy (about 250 MB of weights at runtime) and slower to cold-start than raw ONNX. Keep it off the 2-second hot path.
- **SthPhoenix/InsightFace-REST**: a Dockerised InsightFace REST service with an ONNX Runtime CPU option. Useful only if we want the matcher as a separate container. **Effort: M.**
- **ruhyadi/vision-fr**: an ONNX Runtime pipeline with YOLOX, InsightFace, **pgvector** and FastAPI. It's a compact pattern reference if we store embeddings in Postgres. No license.

Also: `exadel-inc/CompreFace` (8.4k stars, Apache-2.0, last push 2024-10) is a full self-hosted face-recognition server, overkill for today. `ageitgey/face_recognition` (dlib, 57k stars) is less accurate than ArcFace, so skip it.

---

## 7. iOS depth / TrueDepth / ARKit

| Repo | Stars | Pushed | License | Lang |
|---|---|---|---|---|
| [marek-simonik/record3d](https://github.com/marek-simonik/record3d) | 494 | 2025-04-21 | LGPL-2.1 | C++/Python |
| [marek-simonik/record3d-simple-wifi-streaming-demo](https://github.com/marek-simonik/record3d-simple-wifi-streaming-demo) | 22 | 2026-08-21 | MIT | HTML/JS |
| [zeshanahmad1234/TrueDepthExplorer](https://github.com/zeshanahmad1234/TrueDepthExplorer) | 0 | 2026-11-03 | MIT | Swift |
| [davidemonnati/ARFaceDumper](https://github.com/davidemonnati/ARFaceDumper) | 2 | 2026-10-06 | BSD-3-Clause | Swift |

- **Record3D**: the quickest way to get **real TrueDepth RGB-D into Python**. `pip install record3d` streams depth over **USB** from the Record3D iOS app (a paid App Store app, with the LiDAR/TrueDepth streaming feature possibly behind an in-app purchase; check before relying on it). The Wi-Fi demo streams RGB-D over **WebRTC** into a browser (`/getOffer` and `/sendAnswer` on the phone). **Effort: M.** A depth-flatness check (a plane fit on the face ROI: photos and screens are planar) would be a strong extra demo signal. **Gotchas:** the author warns that Wi-Fi depth is noisy and recommends USB for accuracy. The library is LGPL, which is fine to link.
- **TrueDepthExplorer**: a compile-ready SwiftUI app with an ARKit face mesh, 52 blendshapes, a challenge/response liveness tab and a raw `AVCaptureDepthDataOutput` depth tab. CI builds an unsigned IPA. **Effort: M-L.** You need Xcode and a TrueDepth iPhone, and you'd have to add a WebSocket sender to push depth or a "depth-OK" verdict to FastAPI. It was created this month by a single author, so expect rough edges.
- **ARFaceDumper**: an ARKit face-tracking telemetry app that exports mesh and depth. BSD-3, targets iOS 26.2 or later. Reference only.

Treat this whole category as roadmap or stretch work ("depth/IR camera for silicone masks"). It shouldn't be on the critical path today. Also seen: `ToshihiroGoto/ARKit-FaceTracking-DepthImage` (2017, no license) and `flubiewka/TrueDepth` (3 KB, NDI point cloud).

---

## Recommended starter stack (clone these 5)

1. **`yakhyo/uniface`** (pip) plus the **`yakhyo/face-anti-spoofing`** ONNX release weights form the **FastAPI ML core.** Uniface provides SCRFD detection and alignment, the eDifFIQA quality score (feeding the REQUEST VERIFICATION "retake" branch), MiniFASNet and a local ArcFace/AuraFace embedding plus FAISS for threshold tuning. Load the raw yakhyo ONNX pair (V2 at 2.7 plus V1SE at 4.0) directly so we control the "3 of 5 frames ≥ 0.8" fusion. Optionally add **`facenox/face-antispoof-onnx`** (600 KB) as a third vote.
2. **`aws-samples/rekognition-user-vectors`** handles **identity**: copy `helpers.py` for CreateCollection, IndexFaces, CreateUser, AssociateFaces and SearchUsersByImage in ap-south-1. Mirror **`vadimgodev/face-recognition`**'s hybrid logic: local ArcFace ≥ high means a match, the grey zone goes to Rekognition, and low means no match. That's our two-threshold fusion, already coded.
3. **`google-ai-edge/mediapipe-samples` `examples/face_landmarker/js`** is the **React kiosk capture layer.** Wrap it in a hook for the quality lock, head pose, and blendshape step-up challenges (`mouthSmile*`, `jawOpen`, `cheekPuff`). Use `vladmandic/human` `demo/faceid` only as the reference for the gating state machine and blink-speed check, not as a second runtime.
4. **Colour flash** is our own code. The client displays the server-issued colour sequence. Use **`watcharaponthod-code/ekyc` `server/app/flash.py`** as the design and test reference (reimplement it; there's no license), and run the correlation in the FastAPI liveness worker in parallel with matching.
5. **`aws-amplify/amplify-ui` `@aws-amplify/ui-react-liveness`** covers the **step-up path only**: `FaceLivenessDetector` in React, with FastAPI endpoints for `CreateFaceLivenessSession` and `GetFaceLivenessSessionResults` (borrow the Lambda logic from `aws-samples/amazon-rekognition-face-liveness-demo`). It needs a Cognito identity pool, so check sandbox permissions in hour 0. The streaming endpoint exists in ap-south-1.

**How they fit together:**

```
React kiosk  (MediaPipe Face Landmarker sample -> quality lock + flash renderer + blendshape challenges)
    |  3-5 JPEG frames + flash timestamps + session id
    v
FastAPI (EC2 ap-south-1)
    |- asyncio.gather(
    |     liveness:  yakhyo MiniFASNet x2 (+facenox) ; FFT moire ; flash correlation (own, ekyc-style) ; phone detector
    |     identity:  Rekognition SearchUsersByImage (user-vectors helpers) ; uniface ArcFace local check (FaceGuard hybrid)
    |  )
    |- fusion (two thresholds per signal) -> ALLOW / REQUEST VERIFICATION / DENY + reason codes
    v
Step-up: blendshape smile/open-mouth challenge -> (optional) Amplify FaceLivenessDetector -> SES OTP
```

**Licence line for the pitch:** the pipeline code and the MiniFASNet originals are Apache-2.0 or MIT. InsightFace buffalo_l weights and the CelebA-Spoof-trained facenox model are non-commercial research only. For production, swap in AuraFace or SFace and retrain anti-spoof on licensed data.
