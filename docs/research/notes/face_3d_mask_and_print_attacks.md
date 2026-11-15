> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# 3D Mask and Printed-Photo/Paper-Mask Presentation Attacks: Research and Practical Countermeasures for a Webcam Kiosk

Research date: 2026-11-14. This file follows up on face_recognition_active_liveness.md after the user asked to focus on 3D masks and printed attacks. No web-search tool was available, so I fetched primary pages directly (arXiv abstract pages, Idiap and HKBU dataset pages, GitHub). Several full papers (Springer ECCV'16 behind a login, ECVA PDF returning 404) and the arXiv and Semantic Scholar search APIs (HTTP 429) could not be read. Where only an abstract was available, numeric results are listed as gaps.

## What attack types exist, and which public datasets and papers cover them?

### Takeaway
Printed photos, paper-cut masks (with eye holes), rigid 3D resin or plastic masks (ThatsMyFace, REAL-f), and flexible silicone masks are the main physical attacks. Public research datasets are 3DMAD (Kinect RGB+depth), HKBU-MARs (webcam, rPPG-oriented), WMCA (RGB+depth+IR+thermal, 1,941 videos) and CASIA-SURF HiFiMask (54,600 videos, 225 high-fidelity masks). All are research-licensed (EULA or agreement).

### Cited Findings
- **3DMAD:** 17 subjects, 76,500 frames, Microsoft Kinect depth (640×480, 11-bit) plus RGB. 3 sessions × 5 videos × 300 frames; session 3 is mask attacks by one attacker. Life-size masks from ThatsMyFace.com, plus **paper-cut masks** made from the same images. Download from Zenodo 4068477; paper: Erdogmus & Marcel, "Spoofing in 2D Face Recognition with 3D Masks and Anti-spoofing with Kinect", BTAS 2013. — [Idiap 3DMAD](https://www.idiap.ch/en/scientific-research/data/3dmad)
- **HKBU-MARs:** V1 has 8 subjects and masks (6 ThatsMyFace, 2 REAL-f), recorded on a Logitech C920 at 1280×720 in room light. V1+ (ECCV'18) adds 4 REAL-f masks. V2 has 1,008 videos with 12 masks, 7 cameras and 6 lighting settings. Access requires a signed agreement. — [HKBU-MARs](https://rds.comp.hkbu.edu.hk/mars/)
- **Related rPPG papers from HKBU (Liu, Yuen et al.):** ECCV'16, rPPG-based 3D mask anti-spoofing; ECCV'18, rPPG correspondence feature; WACV'20, temporal similarity of rPPG "for faster mask detection"; TIFS'21, multi-channel rPPG correspondence feature. Also Shao et al.: deep dynamic textures for masks (TIFS'19) and multi-adversarial domain generalization (CVPR'19). — [HKBU-MARs](https://rds.comp.hkbu.edu.hk/mars/)
- **WMCA (Idiap):** 1,941 videos of 72 identities. Sensors: Intel RealSense SR300 (color 1920×1080, depth and IR 640×480) and Seek Thermal Compact PRO (320×240). Attack counts: flexible/silicone masks 379, replay 348, print 200, rigid masks 137, fake heads 122 (some heated), glasses 75, paper masks 71, makeup 216, wigs 46; bonafide 347. The preprocessed version is free on Zenodo 4580313 under a EULA. Reference paper: George et al., "Biometric Face Presentation Attack Detection with Multi-Channel CNN", IEEE TIFS 2019. — [Idiap WMCA](https://www.idiap.ch/en/scientific-research/data/wmca)
- **CASIA-SURF HiFiMask:** 54,600 videos, 75 subjects, 225 realistic high-fidelity masks, 7 sensor types. The authors argue that earlier mask benchmarks were small and low-fidelity, and that "basic deep models and rPPG methods" did well on them but fall short in the real world. Proposed method: Contrastive Context-aware Learning (CCL), which uses subject, mask-material and lighting context. — [Liu et al., arXiv 2104.06148](https://arxiv.org/abs/2104.06148)
- **3D High-Fidelity Mask PAD Challenge (on HiFiMask, Protocol 3, open-set):** 195 teams in the development phase, 18 finalists. — [arXiv 2108.06968](https://arxiv.org/abs/2108.06968)
- **Survey (Yu et al., TPAMI):** handcrafted features have "limited representation capacity"; deep FAS approaches use binary or pixel-wise (pseudo-depth) supervision, domain generalization, and multi-modal sensors (depth, IR, light field, **flash**). — [arXiv 2106.14948](https://arxiv.org/abs/2106.14948)

### Inferences
- Paper-cut masks with eye holes (in 3DMAD) let the attacker's **real eyes blink through the mask**. A blink-only challenge is therefore defeated by a cheap printed mask. Challenges must also involve deformation of the mouth and cheeks.

### Gaps
- No ACER/HTER numbers could be retrieved for HiFiMask/CCL, the challenge winners, MC-CNN on WMCA, or the HKBU rPPG papers. Only abstracts or dataset pages were accessible.

## Which detection techniques work for 3D masks and prints, and what do they cost (time, hardware)?

### Takeaway
The research falls into five families:
1. Texture and frequency CNNs (RGB-only, passive, single frame).
2. Pseudo-depth or auxiliary supervision (CDCN, Liu et al. CVPR 2018).
3. rPPG pulse detection (masks block the skin's blood-volume signal, but this needs a multi-second clip).
4. Multi-spectral or depth sensors (RealSense depth, NIR, thermal: the strongest option for masks).
5. Active light or flash reflection (Face Flashing).

For RGB-only and under 2 s, the practical approach layers a passive CNN with active deformation challenges and flash reflectance. rPPG and depth/IR are upgrades.

### Cited Findings
- **CDCN / CDCN++ (CVPR 2020):** Central Difference Convolution combines "intensity and gradient information" to capture fine-grained spoof cues; it works on single frames and is suited to fast-response applications. Results: 0.2% ACER on OULU-NPU Protocol 1 and 6.5% HTER cross-dataset (CASIA-MFSD → Replay-Attack). Code at github.com/ZitongYu/CDCN. — [Yu et al., arXiv 2003.04092](https://arxiv.org/abs/2003.04092)
- **Liu, Jourabloo & Liu (CVPR 2018):** binary live/spoof classifiers "struggle to grasp adequate spoofing cues and generalize poorly". They propose a CNN-RNN with auxiliary supervision of **face depth (pixel-wise)** and **rPPG (sequence-wise)**, fused for the decision, and introduce a dataset with wide illumination, subject and pose variation. — [arXiv 1803.11097](https://arxiv.org/abs/1803.11097)
- **rPPG for masks:** HKBU's ECCV'16 paper introduced rPPG-based 3D mask detection. The WACV'20 follow-up targets faster detection. — [HKBU-MARs](https://rds.comp.hkbu.edu.hk/mars/). HiFiMask's authors note that rPPG methods that did well on older benchmarks fall short on high-fidelity masks in the wild. — [arXiv 2104.06148](https://arxiv.org/abs/2104.06148)
- **Multi-channel sensing:** WMCA records RGB, depth, IR and thermal specifically for PAD research, including heated fake heads to defeat thermal-only checks. — [Idiap WMCA](https://www.idiap.ch/en/scientific-research/data/wmca)
- **Flash reflection:** Face Flashing verifies response timing and "differentiate[s] 2D plane from 3D objects", with 98.8% overall accuracy (97.3% worst case). — [Tang et al., NDSS 2018 / arXiv 1801.01949](https://arxiv.org/abs/1801.01949)
- **Deployable passive RGB model: Minivision Silent-Face-Anti-Spoofing (Apache-2.0).**
  - Architecture: MiniFASNet V1/V2 with about 0.41–0.44M params and 0.081 GFLOPs at 80×80 input, plus an auxiliary Fourier-spectrum branch; multi-scale fusion over face crops at scale 1, 2.7 and 4.
  - Released model: about 20 ms on a mobile SoC, 97.8% TPR at FPR 1e-5. A 99.7% high-precision model is not released.
  - Caveats: sensitive to camera and scenario; face rotation must stay under 30°.
  - The README's definition of fakes includes "printed photos, device screens, silicone masks and 3D portraits", but per-attack performance is not given.
  — [Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- deepface wraps this model through `anti_spoofing=True`, which returns an `is_real` flag. — [deepface](https://github.com/serengil/deepface). InsightFace 2.0 adds an optional RGB liveness add-on (default threshold 0.8, with input-rejection reasons); its weights fall under InsightFace's non-commercial model terms. — [InsightFace](https://github.com/deepinsight/insightface)

### Inferences (recommended layered solution for the kiosk; design inferences, not measured)
1. **Prints and phone or screen replay (cheap attacks):**
   - (a) Passive MiniFASNet on 2–3 frames (about 20–40 ms each on CPU).
   - (b) Flash/color reflection correlation: a print reflects the flash but shows a flat, uniform response; a phone screen emits its own light, so its chroma barely tracks the flash.
   - (c) Head-turn parallax: a tilted print moves its landmarks as a planar homography, while a real head shows non-planar parallax (nose versus cheek offsets). Fit a homography to about 20 rigid landmarks across the turn; low residual means flat, which means spoof.
   - (d) Optional: an object detector (for example COCO "cell phone" or a rectangle or edge detector) to catch phone bezels or paper borders around the face.
2. **Paper-cut masks with eye holes:** blink passes, so require a **mouth/cheek deformation challenge** (smile, open mouth, puff cheeks). Paper cannot deform, so `jawOpen` and `mouthSmile*` blendshapes stay near baseline, or the mesh tears or loses tracking. Also check the eye region: a texture or color discontinuity at the mask's eye-hole border shows up as a high Laplacian ring around the eye landmarks.
3. **Rigid 3D masks (resin, plastic, 3D-printed):** they have correct 3D shape (they defeat parallax and partly defeat the 3D part of flash) but no expression deformation and non-skin reflectance.
   - (a) Deformation challenge (smile or open mouth with a correlated cheek and nasolabial landmark shift).
   - (b) Flash spectral response: compare the face-skin reflectance ratios R/G/B under red, green and blue flashes against a live-skin envelope calibrated on enrolled users. Skin's subsurface scattering differs from resin or paint.
   - (c) Specular highlight check: resin masks often show sharp, uniform specular highlights.
   - (d) Mouth interior: under an "open mouth" challenge, a rigid mask's mouth opening shows the attacker's own lips or a dark gap misaligned with the mesh.
4. **Flexible silicone masks (the hardest; they deform):** RGB-only defenses are weak here. Options:
   - (a) rPPG over the available clip (CHROM/POS on forehead and cheek ROIs). A real face shows a coherent pulse at 0.7–3 Hz across ROIs; silicone attenuates it. Below 2 s, a pulse estimate is unreliable (it covers only about 1.5–3 heartbeats), so use rPPG as a soft signal that can route to REQUEST VERIFICATION and is never the sole ALLOW criterion.
   - (b) Hardware upgrade: an Intel RealSense (depth plus IR) or NIR camera with an 850 nm illuminator. Under NIR, skin and silicone or resin reflect differently, and IR-plus-depth is the standard multi-channel PAD setup (WMCA).
   - (c) A thermal camera helps but can be fooled by heated masks (WMCA includes heated fake heads).
5. **Decision:** any single mask cue firing (no deformation, flat homography, weak or non-skin flash response, no rPPG coherence when it was measurable) moves the decision toward REQUEST VERIFICATION (OTP or a staff check) rather than DENY, unless several cues fire strongly together. This keeps legitimate users from being rejected because of lighting.
6. **Demo test set to build in a day:** printed A4 photo, photo with eyes cut out (paper-cut mask), phone replay, laptop-screen replay, and, if one is available, a 3D-printed or resin mask. Report APCER per attack type and BPCER on live users.

### Gaps
- No quantitative per-attack results were retrieved for MiniFASNet, CDCN on masks (SiW-M), MC-CNN/WMCA, HiFiMask/CCL, or HKBU rPPG methods (EER/HTER and minimum clip length). Their full texts were not accessible (rate limits, paywall, 404).
- No primary source fetched for skin-versus-silicone or resin NIR reflectance values, or for rPPG minimum window lengths. The figures above are background-knowledge estimates and should be validated.
- Commercial certified options (iBeta ISO/IEC 30107-3 Level 2, which covers masks) were not researched in this pass.
