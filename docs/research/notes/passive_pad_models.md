> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# Passive Face Anti-Spoofing (PAD) Models for a One-Day Hackathon (researched 2026-11-14)

Method note: no web-search tool was available. Sources were gathered by fetching GitHub READMEs and repo files directly, and by querying the Hugging Face and GitHub search APIs. The GitHub API search ran on 2026-11-14 and reported star counts and "last pushed" dates as of that day. Benchmark tables for CDCN/CDCN++, DeepPixBiS, and HiFiMask/SiW-M results could not be fetched; they are listed under Gaps rather than quoted from memory.

## Q1. Which pretrained models can be downloaded today and run on CPU in under 200 ms?

### Takeaway
The only family that is clearly drop-in, permissively licensed, and CPU-fast is minivision's MiniFASNet (V1SE/V2, about 0.4M params, 80x80 input, about 1.7-1.9 MB). It comes in several ONNX/TFLite ports, and DeepFace's `anti_spoofing=True` also wraps it. A retrained 128x128 MiniFASNetV2-SE (facenox, Apache-2.0, 600 KB INT8, trained and evaluated on CelebA-Spoof) is the best "newer" lightweight option. InsightFace 2.0 (Sep 2026) adds a one-line `addons=["liveness"]` ONNX model, but its weights are non-commercial. CLIP/ViT-based SOTA (FLIP) has public weights, but each checkpoint is protocol-specific, research-oriented, and about 10x heavier. CDCN and InstructFLIP have no public weights.

### Cited Findings

**minivision-ai/Silent-Face-Anti-Spoofing (the baseline everyone ports)**
- License is Apache-2.0. The repo has about 1.8k stars, and its last listed model update is 2020-07-30 (Caffe models via Baidu Pan). The GitHub API shows the last push as 2023-10-03 — [GitHub](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing); [GitHub API search, 2026-11-14](https://api.github.com/search/repositories?q=face+anti-spoofing)
- MiniFASNetV1: 0.081 GFLOPs and 0.414M params. MiniFASNetV2: 0.081 GFLOPs and 0.435M params. Both are pruned from MobileFaceNet (0.224G / 0.991M). Training adds an auxiliary Fourier-spectrum supervision branch, and the final detector fuses models trained at several crop scales — [GitHub README](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- The open-sourced "APK model" is 84M FLOPs and runs in 20 ms, with TPR 97.8% at FPR 1e-5 (on minivision's internal data). A "high-precision" 162M FLOPs model (TPR 99.7% at FPR 1e-5) is **not released**. Mobile speeds: Kirin 990 19 ms, Snapdragon 845 24 ms, RK3288 90 ms — [GitHub README](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- Claimed attack coverage is printed paper photos, electronic display screens, silicone masks, and 3D portraits. The README also cautions that RGB-only robustness depends on camera model and scenario, and that face rotation should stay under 30° — [GitHub README](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- No public training dataset is named. Users supply their own 3-class folders — [GitHub README](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- The reference `test.py` loads every model in `resources/anti_spoof_models` (the shipped pair is `2.7_80x80_MiniFASNetV2.pth` and `4_0_0_80x80_MiniFASNetV1SE.pth`). It sums their 3-class softmax outputs and takes the argmax. **Label index 1 = real**; 0 and 2 = spoof. The score is the summed probability divided by 2 — [test.py](https://raw.githubusercontent.com/minivision-ai/Silent-Face-Anti-Spoofing/master/test.py)

**Ready ONNX/TFLite ports of MiniFASNet**
- `yakhyo/face-anti-spoofing` (Apache-2.0, pushed 2026-10-20) ships MiniFASNetV1SE (crop scale 4.0) and MiniFASNetV2 (crop scale 2.7, the default) as both `.pth` and `.onnx` GitHub release assets. Each is about 0.43M params. The same models are integrated in the author's UniFace toolkit (MIT) — [GitHub](https://github.com/yakhyo/face-anti-spoofing)
- `garciafido/minifasnet-v2-anti-spoofing-onnx` on Hugging Face (Apache-2.0, 2026-05-04): a 1,744,116-byte ONNX opset-11 export, bit-equivalent to upstream `2.7_80x80_MiniFASNetV2.pth`. Input is (1,3,80,80) float32 **BGR**, /255, with a 2.7x bbox crop and no alignment. YuNet is suggested as the detector — [HF model card](https://huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx)
  - CONFLICT: this card says the output order is `[live, print, replay]`. Upstream `test.py` and the LiteRT card both say **index 1 = live**. Trust upstream and verify on a real image before building on it — [test.py](https://raw.githubusercontent.com/minivision-ai/Silent-Face-Anti-Spoofing/master/test.py); [LiteRT card](https://huggingface.co/litert-community/Silent-Face-Anti-Spoofing-LiteRT)
- `litert-community/Silent-Face-Anti-Spoofing-LiteRT` (Apache-2.0, 2026-07-07, about 1.76k downloads, the most-downloaded FAS model on HF): a 1.85 MB `silentface.tflite` (MiniFASNetV2 2.7_80x80). Measured 2.13 ms p50 on a Raspberry Pi 5 CPU (XNNPACK, 4 threads, 2026-08-31), 1.39 ms in Chromium WebGPU via LiteRT.js on an M4 Max, and about 5 ms on a Pixel 8a GPU. Output is a [1,3] softmax with class 1 = live — [HF model card](https://huggingface.co/litert-community/Silent-Face-Anti-Spoofing-LiteRT)
- Other ports: `QingHeYang/Silent-Face-Anti-Spoofing-onnx` (Apache-2.0, 2025-10) and `feni-katharotiya/Silent-Face-Anti-Spoofing-TFLite` (Apache-2.0, 2025-03) — [GitHub API search, 2026-11-14](https://api.github.com/search/repositories?q=face+anti+spoofing+onnx)

**facenox/face-antispoof-onnx (retrained MiniFASNetV2-SE)**
- Apache-2.0, 277 stars, pushed 2026-10-15. Architecture is MiniFASNetV2 + SE with a Fourier auxiliary loss. Input is a **128x128 RGB** crop with 1.5x padding. Output is binary Real/Spoof. Sizes: .pth 1.95 MB, ONNX 1.82 MB, INT8 ONNX about 600 KB — [GitHub](https://github.com/facenox/face-antispoof-onnx)
- On the CelebA-Spoof evaluation set (70k+ samples) it reports accuracy 98.20%, real accuracy 97.58%, spoof accuracy 98.73%, and ROC-AUC 0.9984 (INT8 is nearly identical). There are no cross-dataset numbers and no published latency; the demo runs CPU-only on a 2011 i7-2630QM — [GitHub](https://github.com/facenox/face-antispoof-onnx)
- Its limitations doc says it is "Good at printed photos and screens. **Not trained on 3D silicone masks** or prosthetics." It needs even lighting (backlight causes errors), a source face of at least 64x64, and ±30° pose. Motion blur hurts, so it recommends requiring 3-5 consecutive "Real" frames. The default threshold is tuned for FPR < 2%, and raising it from 0.5 to 0.8 trades false rejects for security — [LIMITATIONS.md](https://raw.githubusercontent.com/facenox/face-antispoof-onnx/main/docs/LIMITATIONS.md)

**DeepFace `anti_spoofing=True`**
- DeepFace is MIT-licensed. `DeepFace.extract_faces(img_path=..., anti_spoofing=True)` returns an `is_real` field, and `DeepFace.stream(..., anti_spoofing=True)` does the same for real-time use. The README links the feature to the minivision Silent-Face-Anti-Spoofing license and says "License types will be inherited" — [GitHub README](https://github.com/serengil/deepface)
- Inference: DeepFace wraps the same minivision MiniFASNet weights (Apache-2.0), so it adds no new accuracy, only convenience.

**InsightFace 2.0 RGB liveness addon (new, 2026-09-09)**
- `FaceAnalysis(addons=["liveness"], liveness_mode="normal"|"observe", liveness_threshold=0.8)` auto-downloads `liveness.onnx` from the `deepinsight/insightface-model-addons` release (SHA-256 verified). Each face gets `face.liveness.status/is_live/live_score`. In `normal` mode, recognition is skipped for faces that fail liveness — [InsightFace liveness.md](https://raw.githubusercontent.com/deepinsight/insightface/master/python-package/docs/liveness.md)
- Preprocessing uses a fixed 80x80 alignment template from 5-point landmarks and RGB /255, and the model outputs a live probability directly. Crops with more than 30% missing source area are rejected. The docs warn that the 0.8 threshold "is an integration default, not a production accuracy guarantee" — [InsightFace liveness.md](https://raw.githubusercontent.com/deepinsight/insightface/master/python-package/docs/liveness.md)
- The architecture, training data, and benchmarks for `liveness.onnx` are not documented on the addons repo page — [insightface-model-addons](https://github.com/deepinsight/insightface-model-addons)

**CLIP/ViT-based: FLIP (ICCV 2023)**
- The backbone is CLIP ViT-B/16 (16x16 patches, d=768) with 224x224 input. CelebA-Spoof is added as supplementary training data — [arXiv HTML 2309.16649](https://arxiv.org/html/2309.16649)
- Weights are public: 14 checkpoints on MBZUAI SharePoint, one per held-out domain (M, C, I, O, W, CeFA, SURF) in 0-shot and 5-shot versions. No metrics are on the model-zoo page — [FLIP model_zoo.md](https://github.com/koushiksrivats/FLIP/blob/main/docs/model_zoo.md)
- The repo shows no license file. The paper is CC BY-NC-SA 4.0 — [GitHub](https://github.com/koushiksrivats/FLIP); [arXiv](https://arxiv.org/abs/2309.16649)
- Related: `jiwonpark0065/T-FLIP` (MIT, 2024-12) distills CLIP for FAS (lightweight). Its weights and numbers were not checked — [GitHub API search](https://api.github.com/search/repositories?q=FLIP+face+anti-spoofing)

**No public weights (flag these)**
- CDCN / CDCN++ / DC-CDN (`ZitongYu/CDCN`): no pretrained weights in the README or releases. It is "just for research purpose, and commercial use is not allowed." Its claims are 1st place in the CVPR2020 ChaLearn multi-modal track and 2nd place in the single-modal track — [GitHub](https://github.com/ZitongYu/CDCN)
- InstructFLIP (ACM MM 2025, arXiv 2507.12060): no released weights, no license, and no numbers in the README — [GitHub](https://github.com/kunkunlin1221/InstructFLIP)

**Hugging Face community models (low trust)**
- `nguyenkhoa/dinov2_Liveness_detection_v2.2.3` (2025-01; 88 MB safetensors, transformers). It reports 99.32% eval accuracy on an "unknown dataset" and has no license — [HF](https://huggingface.co/nguyenkhoa/dinov2_Liveness_detection_v2.2.3)
- `biometric-ai-lab/Antispoofing` (Apache-2.0 card, 2025-12): a video model (WideResNet-101-2 + Transformer over 10 frames; 50.8 MB `.pth` + 44.7 MB YOLOv8s-face ONNX). It claims photo, replay, and 3D mask coverage. Its reported metrics are inconsistent (train accuracy 80.69% vs validation 99.75%; EER 20.83% vs 1%), and the card's MIT badge conflicts with its Apache metadata — [HF](https://huggingface.co/biometric-ai-lab/Antispoofing)
- Also present but unverified: `nguyenkhoa/mobilevitv2_Liveness_detection_v1.0`, `Molkaatb/Liveness_Vit`, `tienminhtran/face-antispoof-onnx`, and `haroonx02/face-antispoofing-resnet18` (2026-11-02) — [HF API search](https://huggingface.co/api/models?search=liveness)

### Inferences
- For CPU latency under 200 ms on a laptop, MiniFASNet (about 81 MFLOPs) will run in single-digit ms. The budget will be dominated by face detection (RetinaFace/YuNet/SCRFD), not PAD. Even a CLIP ViT-B/16 at 224 (about 17 GFLOPs, a typical figure not sourced here) probably fits in 200 ms on a modern CPU, but this is unmeasured.
- Recommended hackathon stack: an ensemble of minivision V2 (2.7x) + V1SE (4.0x), as upstream does, plus facenox 128x128 INT8 as a third vote, all through onnxruntime. Average the live probabilities and require N consecutive live frames.
- InsightFace's addon is the fastest way to get detection + alignment + liveness in one call. For a hackathon demo the non-commercial license is acceptable, but it would block any commercial product.

### Gaps
- No independent CPU latency (e.g., x86 ms/frame) for MiniFASNet ONNX or FLIP was found. Measure it locally.
- The architecture, training data, and accuracy of the InsightFace `liveness.onnx` addon are undocumented.
- Passive models with public weights from 2024-2026 beyond FLIP (e.g., FAS-SAM, CFPL, UniAttackDetection, FM-ViT) were not verified. Without web search I could not confirm whether any have downloadable weights.
- DeepPixBiS: weights were historically shipped through the Idiap `bob.paper.deep_pix_bis_pad` package; current availability and license were not verified.

## Q2. Reported performance on standard benchmarks, and generalization to masks and unseen attacks

### Takeaway
Intra-dataset numbers are near-saturated (for example, facenox reports 98.2% accuracy and 0.998 AUC on CelebA-Spoof). Cross-domain performance is the real weakness. FLIP, CLIP-based and among the best with public weights, still averages 3.01% HTER zero-shot on MCIO and 8.61% on WCS, where TPR at FPR=1% drops to 58-84%. None of the lightweight models are trained on 3D masks, so mask detection from a single RGB frame should be treated as unreliable.

### Cited Findings
- FLIP-MCL zero-shot results on MCIO (HTER / AUC / TPR at FPR=1%), mean of 5 seeds (ICCV 2023) — [arXiv HTML](https://arxiv.org/html/2309.16649):
  - OCI→M: 4.95 / 98.11 / 74.67
  - OMI→C: 0.54 / 99.98 / 100
  - OCM→I: 4.25 / 99.07 / 84.62
  - ICM→O: 2.31 / 99.63 / 92.28
  - Average HTER 3.01; the 5-shot average is 1.77
  - For comparison, a ViT 0-shot baseline averages 6.00 and ViTAF* 5-shot averages 3.31
- FLIP-MCL zero-shot on WCS (WMCA / CeFA / SURF; includes masks and other diverse attacks) — [arXiv HTML](https://arxiv.org/html/2309.16649):
  - CS→W: 4.46 / 99.16 / 83.86
  - SW→C: 9.66 / 96.69 / 59.00
  - CW→S: 11.71 / 95.21 / 57.98
  - Average HTER 8.61; the 5-shot average is 2.69
- FLIP is not significantly better than the ViT baseline on target M (0-shot or 5-shot), or on target W at 5-shot, per the authors' t-tests — [arXiv HTML](https://arxiv.org/html/2309.16649)
- FLIP attention maps show the cues it relies on: paper texture and edges (M, C), moiré (I, O), screen edges and reflections (W), cloth wrinkles (C), and cut-out eyes or nose (S) — [GitHub README](https://github.com/koushiksrivats/FLIP)
- facenox MiniFASNetV2-SE on CelebA-Spoof: 98.20% accuracy and 0.9984 AUC. It is evaluated on a single dataset only, with no cross-dataset numbers — [GitHub](https://github.com/facenox/face-antispoof-onnx)
- minivision MiniFASNet reports only internal metrics (TPR 97.8% at FPR 1e-5). No public-benchmark numbers are given — [GitHub](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- CelebA-Spoof contains 625,537 images of 10,177 subjects. Its spoof types are print (photo/poster/A4), paper masks (face/upper-body/region), replay (PC/pad/phone), and 3D mask. It covers 4 illumination conditions, indoor/outdoor scenes, and 24 capture devices — [CelebA-Spoof GitHub](https://github.com/Davidzhangyuanhan/CelebA-Spoof)

### Inferences
- In a live demo with a new webcam, lighting, and phone, expect noticeably worse behavior than the reported intra-dataset numbers. Judges holding up a high-resolution phone replay is the most likely failure mode for an RGB-only CNN, which is why the auxiliary cues in Q3 matter.
- Mask attacks: the only cheap mitigations are (a) CelebA-Spoof's 3D-mask class if you fine-tune, and (b) temporal or active cues. Paper masks with cut-outs are partly covered by CelebA-Spoof's paper-mask classes.

### Gaps
- OULU-NPU, SiW, SiW-M, CASIA-SURF, ROSE-Youtu, and HiFiMask numbers for CDCN++, DeepPixBiS, and MiniFASNet could not be retrieved (no search tool, and the CDCN README has no tables). The report writer should not quote CDCN++ OULU ACER figures without a citation.
- No cross-dataset evaluation of the minivision weights on public benchmarks was found.

## Q3. Hand-crafted and auxiliary cues that complement CNNs

### Takeaway
The cheapest high-value add-ons are: (1) a COCO object detector checking for a "cell phone" (class 67) or a laptop/TV overlapping the face, which catches phone and screen replays; (2) an FFT high-frequency/moiré energy check on the face crop, the same signal MiniFASNet's auxiliary branch learns; and (3) temporal consistency (N consecutive live frames). rPPG (pyVHR) is GPL-3.0, its examples use 6-second windows, and it is not reliable in 1-2 seconds.

### Cited Findings
- In the Ultralytics COCO config, class id 67 = "cell phone" — [ultralytics coco.yaml](https://raw.githubusercontent.com/ultralytics/ultralytics/main/ultralytics/cfg/datasets/coco.yaml)
- MiniFASNet adds an auxiliary branch supervised by the Fourier spectrum, and facenox trains with a Fourier-transform auxiliary loss so the model learns "frequency-domain cues that separate real skin from prints and screens." This supports an FFT/moiré feature as a complementary signal — [minivision](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing); [facenox](https://github.com/facenox/face-antispoof-onnx)
- FLIP's attention maps show moiré patterns, screen edges, and reflections as discriminative cues — [FLIP README](https://github.com/koushiksrivats/FLIP)
- Context matters: facenox uses 1.5x padding so the model can "see 3D structure vs flat screens/paper," and minivision uses 2.7x and 4.0x crops that include bezel and background — [facenox LIMITATIONS](https://raw.githubusercontent.com/facenox/face-antispoof-onnx/main/docs/LIMITATIONS.md); [yakhyo](https://github.com/yakhyo/face-anti-spoofing)
- Temporal filtering: require 3-5 consecutive "Real" frames to suppress motion-blur errors — [facenox LIMITATIONS](https://raw.githubusercontent.com/facenox/face-antispoof-onnx/main/docs/LIMITATIONS.md)
- pyVHR facts — [pyVHR GitHub](https://github.com/phuselab/pyVHR):
  - License is GPL-3.0.
  - Methods: GREEN, CHROM, POS, ICA, PCA, SSR, LGI, PBV, OMIT, plus deep MTTS-CAN and HR-CNN.
  - The example uses `wsize = 6` (window size in seconds).
  - The full v2 "requires GPU" (CUDA 11.3, Python 3.9). A CPU-only v1.2 exists (`pyvhr-cpu`).
  - There is a realtime GUI demo, with no latency figures and no stated minimum video length.
- Handcrafted features "become unreliable due to their limited representation capacity" (TPAMI survey, Yu et al., v3 2022-09-02) — [arXiv 2106.14948](https://arxiv.org/abs/2106.14948)

### Inferences
- A 1-2 second capture holds only about 1-2 heartbeats, which is too short for a stable rPPG frequency estimate given that the pyVHR example uses 6-second windows. Use rPPG at most as a soft signal over 5 seconds or more, or skip it. Its GPL-3.0 license is also viral for distribution.
- A practical fusion rule: spoof if any of these holds: a phone, laptop, or TV box contains the face; the CNN ensemble live probability is below the threshold; or the FFT high-frequency ratio is an outlier. Then require K/N live frames. Calibrate the thresholds on about 50 live and spoof captures from the actual demo webcam.
- LBP in HSV/YCbCr and monocular depth (e.g., MiDaS/Depth-Anything to check face flatness) are plausible extra features but were not verified in this research.

### Gaps
- No cited quantitative evidence was found on how well FFT/moiré, LBP color texture, specular reflection, or monocular depth work as standalone PAD on modern phone screens.
- No source was found quantifying rPPG PAD accuracy at 1-2 second windows.

## Q4. Licensing caveats

### Takeaway
MiniFASNet weights and their ports (minivision, yakhyo, garciafido, LiteRT, facenox) are Apache-2.0 and safe for commercial use. InsightFace models, including the new liveness addon by default policy, are non-commercial. CDCN is research-only. FLIP has no code license, and its paper is CC BY-NC-SA. CelebA-Spoof data is non-commercial research only. pyVHR is GPL-3.0.

### Cited Findings
- minivision Silent-Face-Anti-Spoofing: Apache-2.0 — [GitHub](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- facenox, yakhyo, garciafido ONNX, and LiteRT ports: Apache-2.0 — [facenox](https://github.com/facenox/face-antispoof-onnx); [yakhyo](https://github.com/yakhyo/face-anti-spoofing); [garciafido HF](https://huggingface.co/garciafido/minifasnet-v2-anti-spoofing-onnx); [LiteRT HF](https://huggingface.co/litert-community/Silent-Face-Anti-Spoofing-LiteRT)
- DeepFace code is MIT, and wrapped-model licenses are inherited — [deepface](https://github.com/serengil/deepface)
- InsightFace code is MIT, but "The pretrained models provided with this library are for non-commercial research only, whether downloaded automatically or manually." Commercial licensing is by contact (e.g., recognition-oss-pack@insightface.ai, as of the 2025-11-24 update) — [InsightFace python-package README](https://raw.githubusercontent.com/deepinsight/insightface/master/python-package/README.md); [InsightFace README](https://github.com/deepinsight/insightface)
- The InsightFace liveness addon points to the addons release repo "for provenance and applicable notices," but no license text was visible there — [liveness.md](https://raw.githubusercontent.com/deepinsight/insightface/master/python-package/docs/liveness.md); [addons repo](https://github.com/deepinsight/insightface-model-addons)
- CDCN: "research purpose, commercial use is not allowed" — [GitHub](https://github.com/ZitongYu/CDCN)
- FLIP: no license file in the repo, and the paper is CC BY-NC-SA 4.0 — [GitHub](https://github.com/koushiksrivats/FLIP); [arXiv](https://arxiv.org/abs/2309.16649)
- CelebA-Spoof: "available for non-commercial research purposes only." Redistribution is prohibited, and copies are allowed for internal use at a single site — [GitHub](https://github.com/Davidzhangyuanhan/CelebA-Spoof)
- pyVHR: GPL-3.0 — [GitHub](https://github.com/phuselab/pyVHR)

### Inferences
- Any model fine-tuned on CelebA-Spoof, including facenox's, plausibly inherits the dataset's non-commercial restriction, even though the code and weights are labeled Apache-2.0. This is a legal grey area to flag for any post-hackathon product.

### Gaps
- No explicit license was found for the InsightFace `liveness.onnx` addon or for most HF community models.

## Q5. Fast fine-tuning: easily downloadable datasets and training time

### Takeaway
CelebA-Spoof is the only large, diverse, mask-inclusive set downloadable without an approval workflow. The official copy is on Google Drive/Baidu under a click-through non-commercial agreement, and there are ungated Hugging Face mirrors. Fine-tuning MiniFASNet (0.4M params, 80x80) or a ViT head on a CelebA-Spoof subset is feasible within hours on one GPU. OULU-NPU, SiW, SiW-M, CASIA-SURF, and HiFiMask all require signed EULAs and are impractical for a one-day build.

### Cited Findings
- Official CelebA-Spoof is hosted on Google Drive and Baidu (password 61fd), with a Dataset Agreement section and no formal application step described. The release also includes the AENet_C,S,G model with intra-dataset inference code (08/2020) — [GitHub](https://github.com/Davidzhangyuanhan/CelebA-Spoof)
- Ungated Hugging Face mirrors (checked via the API on 2026-11-14):
  - `Ar4ikov/celebA_spoof` (about 1,850 downloads, gated=False, modified 2023-10-09) — [HF](https://huggingface.co/datasets/Ar4ikov/celebA_spoof)
  - `namkuner/CelebA-Spoof-Dataset` (about 504 downloads, gated=False, 2024-08-05) — [HF](https://huggingface.co/datasets/namkuner/CelebA-Spoof-Dataset)
  - `khanhduong/CelebA-Spoof-Silent_FAS` (preprocessed for Silent-FAS) and `nguyenkhoa/celeba-spoof-for-face-antispoofing-test` — [HF API search](https://huggingface.co/api/datasets?search=celeba-spoof)
- Other small HF FAS datasets, some of them vendor samples, include:
  - `AxonData/face-anti-spoofing-dataset` (about 1.6k downloads)
  - `AxonData/Anti_Spoofing_Cut_print_attack`
  - `AxonData/Mannequin_Dataset_Anti_Spoofing`
  - `UniDataPro/anti-spoofing-replay-phone-videos`
  - `akahana/anti-spoofing-casiafasd`
  - [HF API search](https://huggingface.co/api/datasets?search=anti-spoof)
- Training-cost data points:
  - The DINOv2 liveness model was fine-tuned for 5 epochs (512 steps at batch 768, lr 5e-5) to 99.3% eval accuracy on an undisclosed dataset — [HF](https://huggingface.co/nguyenkhoa/dinov2_Liveness_detection_v2.2.3)
  - FLIP trains for only 4,000 iterations at lr 1e-6 — [arXiv HTML](https://arxiv.org/html/2309.16649)
- The facenox repo ships a training pipeline that expects the CelebA-Spoof layout (`metas/labels/train_label.json`, `*_BB.txt` boxes) — [GitHub](https://github.com/facenox/face-antispoof-onnx)
- minivision training takes 3-class folders under `datasets/RGB_Images` and generates Fourier spectra on the fly — [GitHub](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)

### Inferences
- In a one-day hackathon, the best return comes from collecting 5-10 minutes of your own webcam footage (live faces, plus prints and phone replays of teammates) and fine-tuning or calibrating thresholds on it. Training on all of CelebA-Spoof is less valuable than this, given the domain-shift evidence in Q2.
- The full CelebA-Spoof download is very large (625k images), so pull a subset or use a preprocessed HF mirror.

### Gaps
- Exact wall-clock fine-tuning times for MiniFASNet on CelebA-Spoof were not found in any source.
- The size in GB of the HF CelebA-Spoof mirrors and whether they are complete were not verified.
- EULA requirements for OULU-NPU, SiW-M, and HiFiMask were not re-verified for 2026 (they were historically application-based).
