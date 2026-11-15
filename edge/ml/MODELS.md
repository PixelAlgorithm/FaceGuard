# Edge model weights: provenance, SHA-256, licences

All weights are downloaded by `bash scripts/fetch_models.sh` into `models/`, which is gitignored.
Each file is pinned by URL and SHA-256, and the edge re-verifies every SHA-256 at startup
(`edge/ml/registry.py`). Weights are data only: no downloaded code is executed. The pre- and
post-processing code is ours, apart from the numpy helpers imported from the pip package
`uniface==4.3.0` (MIT).

| key | file | SHA-256 | source URL | licence / caveat |
|---|---|---|---|---|
| minifasnet_v2 | `MiniFASNetV2.onnx` | `b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907` | https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV2.onnx | Apache-2.0 (minivision Silent-Face-Anti-Spoofing, ONNX export by yakhyo) |
| minifasnet_v1se | `MiniFASNetV1SE.onnx` | `ebab7f90c7833fbccd46d3a555410e78d969db5438e169b6524be444862b3676` | https://github.com/yakhyo/face-anti-spoofing/releases/download/weights/MiniFASNetV1SE.onnx | Apache-2.0 |
| face_detector | `retinaface_mv2.onnx` | `3ca44c045651cabeed1193a1fae8946ad1f3a55da8fa74b341feab5a8319f757` | https://github.com/yakhyo/uniface/releases/download/weights/retinaface_mv2.onnx | Code MIT (yakhyo/retinaface-pytorch). Trained on WIDER FACE, a research dataset, so check before commercial use |
| arcface | `w600k_r50.onnx` | `4c06341c33c2ca1f86781dab0e829f88ad5b64be9fba56e56bc9ebdefc619e43` | https://github.com/yakhyo/uniface/releases/download/weights/w600k_r50.onnx | **InsightFace buffalo_l recogniser (WebFace600K R50): NON-COMMERCIAL research only.** Fine for the hackathon; production needs a licensed or retrained model, such as AuraFace or EdgeFace via uniface |
| device_detector | `yolox_tiny.onnx` | `427cc366d34e27ff7a03e2899b5e3671425c262ea2291f88bb942bc1cc70b0f7` | https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_tiny.onnx | Apache-2.0 (Megvii YOLOX), COCO-trained. **Not** Ultralytics/AGPL |

PAD self-test fixtures (`models/fixtures/`, data only):

| file | SHA-256 | source | licence |
|---|---|---|---|
| `minivision_image_T1.jpg` (bona fide) | `f4455149f488f76205fdee5499ec5261d08ef6279a1cff7b778ea85405331e94` | minivision-ai/Silent-Face-Anti-Spoofing@b6d5f04ad78778917853b25c778acef6d5626d15 `images/sample/image_T1.jpg` | Apache-2.0 |
| `minivision_image_F1.jpg` (attack) | `4b11b5d7a8a8e4a88f5f16a5426a0a7692e39e5bb45bb03b4ebe5e1606336860` | same repo and commit, `image_F1.jpg` | Apache-2.0 |
| `minivision_image_F2.jpg` (attack) | `fbbea73450ae9d9bb555c8ccac77bf39d234261fe3be4190e3ed2999690c485f` | same repo and commit, `image_F2.jpg` | Apache-2.0 |
| scikit-image `data.astronaut()` (bona fide; bundled in the pip package, no download) | n/a | NASA portrait of Eileen Collins | Public domain (NASA) |

How the SHA-256 values were obtained: the MiniFASNet, RetinaFace and ArcFace values equal the
pins in uniface 4.3.0's `MODEL_REGISTRY`, and they matched the files we downloaded on 2026-11-14.
The YOLOX and fixture values were first computed at download on 2026-11-14 (trust on first use)
and are pinned from then on.

## Pre-processing contracts (verified, see edge/README.md section 4)

| model | input | notes |
|---|---|---|
| MiniFASNetV2 / V1SE | (N, 3, 80, 80) float32 **BGR, raw 0-255** | minivision `CropImage`: scale 2.7 / 4.0, clamped to the image, window **shifted** inside the frame; box = RetinaFace box as `[x, y, w+1, h+1]`; **softmax index 1 = real** (startup self-test) |
| RetinaFace MNv2 | (1, 3, H, W) float32 BGR minus (104, 117, 123) | run on the frame downscaled to a longer side of 320 px; candidate conf 0.5, NMS 0.4 (uniface defaults) |
| ArcFace w600k_r50 | (1, 3, 112, 112) float32 **RGB**, (x - 127.5) / 127.5 | 5-point similarity alignment to the ArcFace template (`uniface.face_utils.face_alignment`); output L2-normalised 512-d. Runs on the CoreML EP only if the CoreML vs CPU cosine is >= 0.9999 at startup (measured 1.000000), otherwise on the CPU EP |
| YOLOX-Tiny | (1, 3, 416, 416) float32 BGR 0-255, letterbox with 114-grey padding, no normalisation | grid/stride decode (strides 8/16/32), score = obj x cls, class-wise NMS 0.45, candidate floor 0.10. Classes from `liveness.device_detector.classes` (COCO-80: 62 tv, 63 laptop, 67 cell phone). Decoding checked on sample images: person 0.93, cat 0.89, cup 0.80 |

Our own code (no third-party code copied): colour-flash correlation (`edge/ml/flash.py`), moire
FFT (`edge/ml/moire.py`), M2 eye-hole ring (`edge/ml/mask.py`), quality and pose proxies
(`edge/ml/quality.py`).
