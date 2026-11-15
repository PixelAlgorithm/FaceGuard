> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# Face Recognition (1:1 / 1:N) and Active Challenge-Response Liveness for a One-Day Webcam Kiosk Prototype

Research date: 2026-11-14. Research note: no web-search tool was available, so findings come from fetching primary sources directly (GitHub READMEs and model zoo pages, Google MediaPipe docs, AWS docs, ONNX Runtime docs, and two primary papers whose PDFs I parsed locally). Several pages I tried could not be read (OpenCV DNN face tutorial returned 403, iProov Flashmark page returned 404, NIST FRTE page was truncated). Those are listed under Gaps.

## Q1. Face recognition stack: detection, alignment, embedding, matching (accuracy, latency, size, license)

### Takeaway
For accuracy in a one-day build, InsightFace `buffalo_l` (SCRFD-10GF detector + ArcFace ResNet50 trained on WebFace600K, ONNX) is the strongest turnkey option: LFW 99.83, IJB-C TAR@FAR=1e-4 of 97.25. `buffalo_s` / `buffalo_sc` (MobileFaceNet, 16 MB for `sc`) is the CPU-friendly fallback. InsightFace pretrained weights are confirmed **non-commercial research only**, and the code is MIT. That suits a hackathon prototype. A commercial product needs a license (InsightFace gives a contact email) or a differently licensed model.

### Cited Findings
**InsightFace (code MIT, weights non-commercial)**
- InsightFace model packs (detector / recognizer / size): antelopev2 = SCRFD-10GF + ResNet100@Glint360K, 407 MB; **buffalo_l = SCRFD-10GF + ResNet50@WebFace600K, 326 MB**; buffalo_m = SCRFD-2.5GF + R50@WebFace600K, 313 MB; buffalo_s = SCRFD-500MF + MBF@WebFace600K, 159 MB; **buffalo_sc = SCRFD-500MF + MBF@WebFace600K, 16 MB, recognition only (no 2d106/3d68/attribute models)**. — [InsightFace model zoo](https://github.com/deepinsight/insightface/tree/master/model_zoo)
- Pack accuracy: buffalo_l scores MR-ALL 91.25, LFW 99.83, CFP-FP 99.33, AgeDB-30 98.23, IJB-C(E4) 97.25. buffalo_s scores MR-ALL 71.87, LFW 99.70, CFP-FP 98.00, AgeDB 96.58, IJB-C(E4) 95.02. buffalo_m reportedly matches buffalo_l and buffalo_sc matches buffalo_s. IJB-C is reported only at FAR=1e-4. — [InsightFace model zoo](https://github.com/deepinsight/insightface/tree/master/model_zoo)
- ArcFace backbone scaling (MR-ALL on Glint360K): R18 72.07, R34 83.02, R50 87.08, R100 90.66. R50 on WebFace600K: MR-ALL 90.57, LFW 99.80, IJB-C(E4) 97.12. Legacy R100 MS1MV2 ArcFace: LFW 99.77. MobileFaceNet: 450M FLOPs, 13 MB. — [InsightFace model zoo](https://github.com/deepinsight/insightface/tree/master/model_zoo)
- SCRFD detectors on WIDER Face at VGA resolution (Easy/Medium/Hard, params, inference ms as listed): 500M 90.57/88.12/68.51, 0.57M, 3.6 ms; 2.5G 93.78/92.16/77.87, 0.67M, 4.2 ms; 10G 95.16/93.87/83.05, 3.86M, 4.9 ms. `_KPS` variants also output 5 keypoints, which are used for alignment. The page does not say what hardware the timings came from. — [InsightFace model zoo](https://github.com/deepinsight/insightface/tree/master/model_zoo)
- License, quoted: "The pretrained models provided with this library are for non-commercial research only", "whether downloaded automatically or manually"; "Model licenses apply separately from the library's MIT license." — [InsightFace python-package README](https://github.com/deepinsight/insightface/tree/master/python-package). The model zoo says: "ALL models are available for non-commercial research purposes only." — [model zoo](https://github.com/deepinsight/insightface/tree/master/model_zoo)
- Commercial licensing contacts: for open-sourced recognition models such as buffalo_l, recognition-oss-pack@insightface.ai; for the InspireFace SDK and advanced models, contact@insightface.ai. — [InsightFace main README](https://github.com/deepinsight/insightface)
- Recent releases: InsightFace 2.0 (2026-09-09) added an "optional RGB liveness addon" with normal/observe modes, per-face scores and input-rejection reasons, plus `raccoon_s`/`raccoon_l` packs and automatic CoreML/CUDA/CPU provider selection. 2.1 (2026-10-03) added PersonAnalysis (`cheetah_s`/`cheetah_l`). InsightFace Server (2026-07-27) is a self-hosted REST "simple AWS Rekognition alternative" with INT8 embedding quantization. — [InsightFace main README](https://github.com/deepinsight/insightface)
- Python package: requires Python ≥3.10. `FaceAnalysis()` defaults to buffalo_l. `prepare()` defaults to an "Auto" detection size combining 128×128 and 640×640. ONNX Runtime providers are tried in the order CoreML → CUDA → CPU. The liveness add-on is enabled with `FaceAnalysis(addons=["liveness"])` and has a default threshold of 0.8. — [python-package README](https://github.com/deepinsight/insightface/tree/master/python-package)
- InsightFace took 1st place on the VISA track of NIST-FRVT 1:1 (2021-10-29) with Partial FC. — [InsightFace main README](https://github.com/deepinsight/insightface)

**AdaFace (quality-adaptive margin)**
- IJB-C TAR@FAR=0.01%: R100 WebFace12M 97.66, R100 WebFace4M 97.39, R50 WebFace4M 96.98, R18 WebFace4M 94.99. For comparison, ArcFace R100 MS1MV2 scores 96.03. LFW is about 99.8 for R50/R100. TinyFace (low-quality) rank-1: 72.29 for R100 WebFace12M. — [AdaFace GitHub](https://github.com/mk-minchul/AdaFace)
- Code is MIT. The README gives no explicit license for the weights. Input is a 112×112 **BGR** crop aligned with MTCNN landmarks, normalized with mean 0.5 / std 0.5. The README warns that InsightFace expects RGB. It is a vanilla PyTorch model with no documented ONNX weights. CVLFace is now the official repo. — [AdaFace GitHub](https://github.com/mk-minchul/AdaFace)

**deepface (wrapper library)**
- MIT-licensed wrapper with 11 recognizers (VGG-Face is the default; also Facenet, Facenet512, OpenFace, DeepFace, DeepID, ArcFace, Dlib, SFace, GhostFaceNet, Buffalo_L) and many detectors (opencv is the default; also retinaface, mediapipe, yunet, yolov8/11/12, centerface, and others). Wrapped models "inherit" their own licenses. `anti_spoofing=True` gives an `is_real` flag via MiniVision Silent-Face-Anti-Spoofing. `register`/`identify`/`search` support pgvector, qdrant, milvus, pinecone, weaviate, redis, postgres, and others, with ANN search through `search_method="ann"`. — [deepface GitHub](https://github.com/serengil/deepface)
- deepface's pre-tuned **cosine distance** thresholds (distance = 1 − cosine similarity; match if distance ≤ threshold): ArcFace 0.68, Buffalo_L 0.55, Facenet512 0.30, Facenet 0.40, SFace 0.593, GhostFaceNet 0.65, VGG-Face 0.68, Dlib 0.07. euclidean_l2 thresholds: ArcFace 1.13, Buffalo_L 1.1, Facenet512 1.04. — [deepface threshold.py](https://raw.githubusercontent.com/serengil/deepface/master/deepface/config/threshold.py)
- deepface converts distance to a 0–100 "confidence" with a per-model logistic fit (`z = w*distance + b`, sigmoid, then remapped so matches fall in 51–100 and non-matches in 0–49). — [deepface verification.py](https://raw.githubusercontent.com/serengil/deepface/master/deepface/modules/verification.py)

**face_recognition (dlib)**
- MIT. dlib ResNet encodings report 99.38% on LFW. Default Euclidean tolerance is 0.6 ("lower numbers make face comparisons more strict"), and the README suggests 0.54 if there are false matches. Caveats: works poorly on children; accuracy varies across ethnic groups, with lower accuracy reported for Asian faces. Windows is not officially supported. The repo has 776 open issues and 57 open PRs, and Python support is listed as 3.3+/2.7. — [face_recognition GitHub](https://github.com/ageitgey/face_recognition)

**Browser options for recognition**
- vladmandic/human (MIT): runs in the browser on WebGPU/WebGL/WASM, using BlazeFace detection, 468-point FaceMesh, MediaPipe Iris and HSE FaceRes descriptors. It has Face Match and Face ID demos; the Face ID demo validates webcam input before matching against IndexedDB. It is built on TF.js 4.10 and does not support Node 23. — [vladmandic/human](https://github.com/vladmandic/human)
- ONNX Runtime Web (`onnxruntime-web`) has `wasm` (the CPU default, full operator coverage) and the GPU providers `webgpu`, `webgl` and `webnn`, which support "only a subset" of operators. Converting to ORT format reduces binary size and startup time. — [ONNX Runtime Web docs](https://onnxruntime.ai/docs/tutorials/web/)

### Inferences
- **Recommended pipeline (server or kiosk-local Python):** InsightFace `FaceAnalysis(name="buffalo_l", allowed_modules=["detection","recognition"])` with `prepare(ctx_id=-1, det_size=(640,640))`, or `(320,320)` for kiosk distance to cut latency. Then use `face.normed_embedding` (512-d, L2-normalized) and cosine similarity = dot product. SCRFD's 5 keypoints feed InsightFace's built-in `norm_crop` similarity-transform alignment to 112×112. If CPU latency is too high, switch to `buffalo_sc` (16 MB) and accept roughly 2 points lower IJB-C. My estimate, not measured here: buffalo_l det+rec on a modern laptop CPU should take tens of milliseconds to around 150 ms per frame, which fits a 2 s budget because recognition runs on only 1–3 selected frames.
- **Threshold convention:** InsightFace practitioners usually threshold cosine *similarity*. deepface's Buffalo_L cosine *distance* 0.55 equals similarity ≥ 0.45, and its ArcFace distance 0.68 equals similarity ≥ 0.32. These are tuned for equal-error-style accuracy on benchmark pairs, not for a FAR target. For FAR 0.1%/0.2%, calibrate on your own impostor pairs (see Q6). For a hackathon, starting at similarity ≈0.45–0.50 for ALLOW and ≈0.30–0.35 for the lower DENY boundary, with the band between them going to REQUEST VERIFICATION, is consistent with these sources, but it is my inference.
- AdaFace is slightly more accurate on low-quality faces but needs PyTorch, MTCNN alignment and BGR care, so it carries more integration risk in a day. face_recognition/dlib is easy to install but weaker, with known demographic issues. deepface is the fastest way to try several models and pgvector storage.
- Browser-only recognition is possible: an ArcFace/MBF ONNX model in onnxruntime-web, or Human's FaceRes. The recognition model's license still applies, and moving matching to the client weakens trust, so do server-side matching for anything security-relevant.

### Gaps
- No primary source found giving cosine-similarity thresholds for buffalo_l at FAR 1e-3 / 2e-3. The InsightFace issue I checked (#1585) contains no thresholds. Calibrate empirically.
- No first-party CPU latency figures for buffalo_l/buffalo_s recognition. The SCRFD ms figures do not state the hardware.
- Could not retrieve current NIST FRTE 1:1 leaderboard content (page truncated). The FaceNet (davidsandberg) and OpenCV SFace/YuNet pages were not retrieved (403).

## Q2. Enrollment best practices: multiple templates, quality checks, storage, template protection

### Takeaway
Enroll 3–5 quality-gated captures per person (frontal plus slight yaw), store L2-normalized 512-d float32 embeddings (not raw images if avoidable), and match against max-of-templates or a mean template. For under 10k identities, a numpy matrix or pgvector is plenty.

### Cited Findings
- AWS Face Liveness returns a "high-quality image called reference image that can be used for face match or face search" and up to four audit images. This pattern ties the enrollment/verification image to the liveness session. — [AWS Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- deepface supports `register`/`search` against pgvector, qdrant, milvus, redis, postgres and others, with ANN search. — [deepface GitHub](https://github.com/serengil/deepface)
- InsightFace Server uses INT8 embedding quantization for large-scale search ("50M+ image search on one RTX 5090 GPU"). — [InsightFace main README](https://github.com/deepinsight/insightface)
- AdaFace's TinyFace results (rank-1 72% vs about 97% on IJB-C) show how much accuracy drops on low-quality faces, which is why enrollment quality matters. — [AdaFace GitHub](https://github.com/mk-minchul/AdaFace)
- face_recognition notes that accuracy is worse for children and varies by ethnicity, so per-population threshold checks are warranted. — [face_recognition GitHub](https://github.com/ageitgey/face_recognition)

### Inferences
- **Quality gates at enrollment and probe (thresholds are engineering heuristics, not from sources):** a single face only; SCRFD det_score ≥ 0.6; inter-ocular distance ≥ 60–80 px (Soukupová & Čech's Eyeblink8 videos averaged 62.9 px IOD, see Q3); yaw and pitch ≤ 15–20° (from the MediaPipe transformation matrix or solvePnP); blur via variance of Laplacian on the aligned crop above an empirically chosen floor (for example about 100 on 112×112, tuned on your camera); mean face-region luma between about 60 and 200 with less than 5% clipped pixels; eyes open (blendshape eyeBlink < 0.4); no occlusion, approximated by MediaPipe presence/landmark confidence.
- **Templates:** keep each enrollment embedding and score a probe as max cosine (or mean of top-2) across them. Optionally add a high-confidence verified probe back as a new template, capped at N, to adapt to appearance changes (template update). Watch for template poisoning.
- **Storage:** for a prototype, use `np.float32 [N,512]` with a `probe @ T.T` dot product for 1:N (sub-millisecond for thousands of identities). Use pgvector (`vector(512)`, `<=>` cosine operator) if you already run Postgres, and FAISS `IndexFlatIP` beyond about 100k. Store model name and version with each template, because embeddings from different models are incompatible.
- **Template protection:** encrypt at rest (AES-GCM with a KMS/env key); keep no raw images, or encrypt them separately with a retention limit. Hashing is not possible because embeddings are noisy. Cancelable approaches such as a random orthogonal projection per tenant or a salt matrix keep cosine similarity unchanged and allow revocation; ISO/IEC 24745 is the relevant standard (named from background knowledge, not fetched). Get consent and allow deletion (GDPR/BIPA biometric data).

### Gaps
- Did not retrieve ISO/IEC 29794-5 (face image quality) or ISO/IEC 24745 texts, or NIST guidance on the number of templates. The recommendations above are engineering inferences.

## Q3. Active liveness: MediaPipe Face Landmarker, EAR blink, head pose, randomized challenges, under 2 s

### Takeaway
MediaPipe Face Landmarker gives everything needed for active challenges in a single model: 478 3D landmarks, 52 blendshapes (eyeBlink*, jawOpen, mouthSmile*, and others) and a 4×4 facial transformation matrix for head pose. It runs on Web, Python, Android and iOS. A randomized 2-step challenge (for example "blink" then "turn left", or "smile"), with roughly 600–800 ms per step, fits a 2 s budget. Blink is natively about 100–400 ms. Detection by EAR threshold 0.2 or blendshape threshold is established practice.

### Cited Findings
- Face Landmarker outputs 478 3D landmarks, 52 blendshape scores (0–1, e.g. `eyeBlinkRight`, `jawOpen`, `browInnerUp`) and an optional 4×4 facial transformation matrix (canonical face to observed pose). Left/Right refer to the subject, and mirroring the image inverts them. — [MediaPipe Face Landmarker guide](https://developers.google.com/edge/mediapipe/solutions/vision/face_landmarker)
- Running modes are IMAGE, VIDEO and LIVE_STREAM. **On Web only IMAGE and VIDEO are supported**; the guide recommends VIDEO mode with `requestAnimationFrame` for a webcam. Options: `numFaces`=1 (temporal smoothing only applies when set to 1), min detection/presence/tracking confidence 0.5, `outputFaceBlendshapes`=false and `outputFacialTransformationMatrixes`=false by default (both must be set to true). — [MediaPipe Face Landmarker guide](https://developers.google.com/edge/mediapipe/solutions/vision/face_landmarker)
- The `face_landmarker.task` bundle (float16) contains a BlazeFace short-range detector (192×192 input), FaceLandmarker-V2 mesh (256×256) and a blendshape model (1×146×2 input). Packages: `@mediapipe/tasks-vision` (Web) and `mediapipe` (Python). — [MediaPipe Face Landmarker guide](https://developers.google.com/edge/mediapipe/solutions/vision/face_landmarker)
- EAR = (‖p2−p6‖ + ‖p3−p5‖) / (2‖p1−p4‖) over 6 eye landmarks. It is roughly constant while the eye is open and approaches 0 when it closes; it is invariant to scale and in-plane rotation and is averaged over both eyes. The baseline threshold is **t = 0.2**. A more robust detector is a linear SVM on a 13-frame window (±6 frames at 30 fps). On the harder Eyeblink8 set, plain thresholding "lags behind" the SVM, because a low EAR can also come from deliberate closure, yawning, expressions or landmark noise. — [Soukupová & Čech, CVWW 2016](https://vision.fe.uni-lj.si/cvww2016/proceedings/papers/05.pdf)
- Test videos ran at 30 fps, 640×480, average IOD 62.9 px. — [Soukupová & Čech, CVWW 2016](https://vision.fe.uni-lj.si/cvww2016/proceedings/papers/05.pdf)
- AWS uses an active "FaceMovementChallenge": move the face into an oval. FaceMovementAndLightChallenge adds colored lights and is "the best setting to maximize accuracy". AWS recommends combining liveness with other signals such as OTP and geolocation, and testing thresholds on your own content. — [AWS Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)

### Inferences
- **Blink:** use MediaPipe `eyeBlinkLeft`/`eyeBlinkRight` blendshapes (pass if both rise above about 0.5 and return below about 0.2 within 400 ms) or EAR from mesh landmarks. Commonly used MediaPipe indices are, for the left eye, 362, 385, 387, 263, 373, 380 and, for the right eye, 33, 160, 158, 133, 153, 144; verify them against the canonical mesh. Require the close-open transition, not just a low value, to reject printed closed-eye photos.
- **Head turn:** take yaw from the facial transformation matrix (`yaw = atan2(-R[2,0], sqrt(R[0,0]²+R[1,0]²))` or similar), or run OpenCV `solvePnP` (6 landmarks such as nose tip, chin, eye corners and mouth corners against a generic 3D model, with focal length about image width). Pass a "turn left" challenge when |yaw| > 15–20° in the commanded direction, followed by a return to frontal. Also check that the 2D landmark geometry changes consistently with 3D rotation; a flat photo that is tilted gives a perspective (homography) change, not parallax.
- **Smile:** pass when (`mouthSmileLeft` + `mouthSmileRight`)/2 > about 0.5 relative to a neutral baseline measured during the first 200 ms.
- **Randomization:** pick 2 of {blink, left, right, smile, open mouth} with a random order and random inter-step timing, issued only after the face is locked. Reject if the response arrives before the prompt or after more than about 1 s (a pre-recorded video cannot anticipate the order). Run face recognition on frames from the challenge window, and check that the identity stays the same (embedding similarity between first and last frame) so a live accomplice cannot swap in.
- **2 s budget (my estimate):** about 300 ms face lock and quality, then challenge 1 (about 700 ms), then challenge 2 (about 700 ms), then about 200 ms for decision and recognition on the best frame. If the user is slow, extend once, then go to REQUEST VERIFICATION rather than DENY.
- **Limits:** active challenges defeat static photos and naive replay, but not a real-time puppeteered deepfake or injection through a virtual camera. Add the flash challenge (Q4) and kiosk camera hardening.

### Gaps
- MediaPipe does not publish latency figures for Face Landmarker on the guide page, and model file size is not stated there.
- No primary source found for blendshape threshold values for blink or smile; they are empirical.

## Q4. Flash / color-reflection challenge (Face Flashing, AWS, iProov) and why it defeats replay and screens

### Takeaway
The screen flashes a random sequence of colors. The camera checks that (a) the face reflects that color in the expected frames (timing), and (b) the reflection pattern looks like a 3D, skin-like object rather than a flat, emissive screen or print. This is what AWS "FaceMovementAndLightChallenge" and the academic Face Flashing protocol do (98.8% accuracy in that paper). A simple version is feasible in a day: 4–6 random colors at about 150–250 ms each, which is about 1 s.

### Cited Findings
- AWS FaceMovementAndLightChallenge: after the face enters the oval, "the Amplify SDK displays a sequence of colored lights on the screen" and streams the video for cloud analysis. It returns a 0–100 confidence score, a reference image, up to 4 audit images, and feedback codes for low-confidence sessions. FaceMovementChallenge (no lights) trades accuracy for speed. — [AWS Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- AWS says thresholds "should reflect your use case": deny or send to another method below threshold. It advises combining liveness with OTP/geolocation and securing the capture device. — [AWS Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- Face Flashing (NDSS 2018) "randomly flash[es] well-designed pictures on a screen and analyz[es] the reflected light". It exploits "reflection processing at the speed of light, unique textual features, and uneven 3D shapes". Overall liveness accuracy was 98.8%, falling to 97.3% in the worst case. — [Tang et al., NDSS 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03B-5_Tang_paper.pdf)
- Face Flashing verifies in three layers: (1) **timing verification** against forged and replayed responses; (2) **face verification**, which checks that the object has a real face's 3D shape (a 2D plane gives a different reflection pattern); (3) face recognition of the claimed identity. A session uses "tens of challenges", so guessing a sequence is unlikely. — [Tang et al., NDSS 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03B-5_Tang_paper.pdf)
- Timing security argument: a screen cannot be updated mid-refresh, and the camera integrates light over its exposure. The paper models a 60 fps camera and 60 Hz screen against an attacker with 240 fps/240 Hz equipment, and shows that the attacker's capture-forge-display loop introduces a detectable delay of at least one frame. Real-time media-based forgery would have to rebuild 3D-consistent reflections in under about one refresh interval. — [Tang et al., NDSS 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_03B-5_Tang_paper.pdf)

### Inferences
- **Hackathon implementation (browser):**
  1. Make the kiosk page fullscreen and set brightness to maximum. Ask for a dim-ish environment, or detect ambient light and fall back if the room is too bright.
  2. Generate a random sequence server-side, for example 5 colors from {red, green, blue, white, black}, each lasting 150–250 ms with random lengths, plus a nonce.
  3. Paint a fullscreen `<div>` with each color and log `performance.now()` per frame via `requestVideoFrameCallback` (Chromium) for capture timestamps.
  4. For each frame, take the mean RGB of the face skin region (MediaPipe cheek/forehead landmark polygons) minus the mean of the background, and normalize chromaticity (r/(r+g+b) and so on).
  5. Correlate the observed chroma time series with the emitted sequence, allowing a lag of 1–3 frames. Pass if the correlation exceeds about 0.7 and the lag is small and stable. Replayed video would show the wrong colors or extra lag.
  6. Optional 3D check: compare the reflection-intensity ratio of nose/cheeks against forehead or edges. A flat screen or print reflects uniformly, while a real face shows shading falloff. A phone screen held up to the camera also emits its own light, so its luminance barely responds to the flash.
- The flash check works best within about 30–60 cm and in modest ambient light. It degrades under bright sunlight, with auto-exposure or white balance, or on low-brightness screens. If the camera allows it, lock exposure and white balance through `MediaStreamTrack.applyConstraints({exposureMode:'manual', whiteBalanceMode:'manual'})` (support varies). A weak signal should go to REQUEST VERIFICATION, not DENY.
- Accessibility: rapid color flashing carries a photosensitive epilepsy risk. Keep flashes at or below 3 per second, or use gentle color transitions; WCAG 2.3.1 sets a three-flashes-per-second limit (background knowledge, not fetched).
- Neither active challenges nor the flash check defeat a virtual-camera injection that renders reflections. On a kiosk, mitigate with a locked-down OS and allow-listed camera device IDs.

### Gaps
- The iProov Flashmark technology page returned 404, so iProov specifics (sequence length, certifications) are not cited.
- No Apple primary source was fetched. Apple Face ID uses an IR dot projector and flood illuminator, not screen color flashes (background knowledge, uncited).
- AWS's exact flash duration and color count are not documented on the fetched page.

## Q5. Browser-side inference options and laptop latency

### Takeaway
Use MediaPipe Tasks for Web (`@mediapipe/tasks-vision`, FaceLandmarker in VIDEO mode, GPU delegate) for landmarks, blendshapes and pose in the browser. Use onnxruntime-web (WASM by default, WebGPU when available) if the embedding must run client-side, and vladmandic/human for an all-in-one TF.js solution. For security, keep the final match and decision on the server.

### Cited Findings
- MediaPipe Web supports IMAGE and VIDEO modes only, through `@mediapipe/tasks-vision`. For webcams, pair VIDEO mode with `requestAnimationFrame`. — [MediaPipe Face Landmarker guide](https://developers.google.com/edge/mediapipe/solutions/vision/face_landmarker)
- onnxruntime-web execution providers: `wasm`/`cpu` (all operators), plus `webgpu`, `webgl` and `webnn` (subset of operators). The ORT format gives smaller binaries and faster startup. Reasons to run in the browser: privacy, offline use, lower server cost. Run on the server if the model is too large or you do not want it downloaded. — [ONNX Runtime Web docs](https://onnxruntime.ai/docs/tutorials/web/)
- vladmandic/human backends: WebGPU, WebGL (default), WASM and CPU, with WebWorker support and frame-change detection to skip work. Chromium is the primary target. — [vladmandic/human](https://github.com/vladmandic/human)

### Inferences
- Architecture suggestion: the browser runs MediaPipe at about 30 fps for UI guidance, quality gates, the challenge state machine and the flash chroma signal. It uploads 2–4 selected JPEG frames plus a per-frame landmark/chroma time series to a FastAPI server. The server runs InsightFace buffalo_l embedding and matching, recomputes the liveness signals on the uploaded frames (never trust a client score alone), and returns the decision.
- Download sizes to expect: the MediaPipe `.task` bundle is a few MB (my estimate; not stated on the page), buffalo_sc recognition is 16 MB, and ArcFace R50 is about 170 MB (the pack is 326 MB in total), which is too large for a quick browser load. Prefer MBF (about 13 MB) for client-side embedding.

### Gaps
- No primary latency benchmarks were found for Face Landmarker Web or onnxruntime-web ArcFace on laptops. Measure on the target kiosk with `performance.now()`.

## Q6. Low-confidence triggers and fusing liveness + match into ALLOW / REQUEST VERIFICATION / DENY

### Takeaway
Use a three-zone decision with two thresholds per score: a high ALLOW threshold at a strict FAR (e.g. 0.1%) and a lower DENY threshold. Anything between them, and any quality failure (lighting, occlusion, pose, blur, multiple faces, weak flash signal, slow challenge), goes to REQUEST VERIFICATION (recapture or OTP). Calibrate thresholds on your own genuine and impostor pairs and attack attempts. AWS explicitly recommends this test-and-tune approach and combining scores with OTP.

### Cited Findings
- AWS: "You can set thresholds for Face Liveness and face match confidence scores... If denied, ask the user to try again or send them to another method." It returns feedback codes for low-confidence sessions so the UI can give retry guidance, and it says to decide thresholds "after testing Liveness performance with various confidence score thresholds on their specific content." — [AWS Rekognition Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- InsightFace's liveness add-on exposes per-face scores and "input-rejection reasons" (default threshold 0.8), which can serve as a quality/PAD signal. — [InsightFace main README](https://github.com/deepinsight/insightface); [python-package README](https://github.com/deepinsight/insightface/tree/master/python-package)
- deepface maps distance to a calibrated-looking 0–100 confidence with a fitted logistic (Platt-style) function per model. — [deepface verification.py](https://raw.githubusercontent.com/serengil/deepface/master/deepface/modules/verification.py)
- Recognition accuracy drops sharply on low-quality faces (TinyFace rank-1 about 72%). — [AdaFace GitHub](https://github.com/mk-minchul/AdaFace)

### Inferences
- **Threshold calibration for FAR 0.1% / 0.2%:** collect genuine pairs (same person, different sessions) and impostor pairs on the kiosk camera. Even 30 people × 10 captures gives about 43k impostor pairs. Set T_allow as the 99.9th percentile (FAR 0.1%) or 99.8th percentile (FAR 0.2%) of the impostor cosine-similarity distribution. For 1:N with N enrolled identities, the effective FAR is about N × the per-comparison FAR, so tighten the threshold (or require a top-1 vs top-2 margin of about 0.1 or more). If data is scarce, start from the deepface Buffalo_L value (similarity 0.45) as T_allow and raise it after observing impostor scores. Fit Platt scaling (logistic regression) to map similarity to P(match).
- **Fusion rule (simple and explainable):**
  - Hard gates first. If the quality gate fails (no face, multiple faces, IOD under 60 px, |yaw| over 20° on the recognition frame, blur, luma outside range, occlusion or low landmark presence) → REQUEST VERIFICATION with a recapture hint. Allow at most 2 recaptures, then offer OTP.
  - Liveness score L in [0,1] = weighted combination of challenge pass (binary per step, with response timing), flash correlation, and optional passive PAD (InsightFace add-on or MiniVision). Match score M = calibrated P(match).
  - **ALLOW:** L ≥ L_hi and M ≥ T_allow and identity consistent across the challenge frames.
  - **DENY:** L ≤ L_lo (a clear spoof, e.g. flash correlation near 0 or wrong challenge order), or M < T_deny for a 1:1 claimed identity.
  - **REQUEST VERIFICATION:** everything else, including timeouts, a weak flash signal under bright ambient light, M between T_deny and T_allow, or a 1:N top-2 margin that is too small.
  - Optionally use a log-likelihood-ratio sum: fused = logit(L) + logit(M), with two cutoffs fit on a small labeled set of genuine, impostor and attack attempts (photo, phone replay, screen).
- Log every decision with its component scores and keep audit frames, similar to AWS's audit images, for tuning and demos.

### Gaps
- No public source provides calibrated FAR-specific thresholds for buffalo_l on webcam data, or standard fusion weights. These must be estimated from local data.
- ISO/IEC 30107-3 (PAD testing; APCER/BPCER metrics) was not fetched. Use APCER/BPCER terminology when reporting attack test results.
