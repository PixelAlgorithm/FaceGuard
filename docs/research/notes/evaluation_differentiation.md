> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# Evaluating and Differentiating a Face PAD (Liveness) + Face Authentication Hackathon Prototype

Context: hackathon judged on Problem-Solution Fit 25%, Innovation 20%, Technical Implementation 25%, Functionality/Usability 15%, Presentation 15%. HID's target slide: 99.4% liveness accuracy, 99.2% face auth accuracy, 0.2% FAR, 0.6% FRR, decision under 2 s, validated on printed photo, screen replay, video and mask. Research date: 2026-11-14.

Method note: I had no web search tool, only direct page fetches. hidglobal.com and iso.org returned HTTP 403, and several vendor blog URLs returned 404. Every claim tagged with a source below was read during this session. Material I could not fetch is either marked "background knowledge, not verified this session" under Inferences or listed under Gaps.

## Q1. Standard metrics: ISO/IEC 30107-3, iBeta Level 1/2/3, and FIDO certification

### Takeaway
Judges in this field expect PAD results as APCER for each attack species (report the worst species, not an average) plus BPCER, and full-system results as IAPMR plus FMR/FNMR. HID's single "99.4% accuracy" number is not an ISO metric. If the team reports in ISO terms, follows an iBeta Level 1-style protocol (6 species, 150 attacks alternated with 50 genuine attempts, a 0% attack-success target, BPCER ≤ 15%), and quotes FIDO's zero-error statistics (rule of 3 / 1.61/N), it will stand out on Technical Implementation.

### Cited Findings
**iBeta (ISO/IEC 30107-3 conformance testing)**
- Every iBeta evaluation uses 6 attack species, chosen "as uniformly as possible". Full-system tests use 6 subjects and/or 6 species. Subjects are cooperative volunteers who pose for photos and videos or sit for live casts, which iBeta calls a "more conservative test". — [iBeta PAD page](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Level 1 allows equipment "readily available in a normal home or office environment", with artefacts costing no more than $30, 8 hours per subject or species (48 h in total), and no tester expertise required. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Level 1 liveness-only testing aims "to present 150 attacks alternated with 50 genuine presentations" in the 8-hour window. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Level 2 allows more costly tools "such as a 3D printer, resin mask, latex mask", artefacts up to $300, 2–4 days per subject or species, and testers with "moderate" expertise (at least one prior PAD test in the same modality). — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Pass criteria: Level 1 allows "0% penetration or match rate" and Level 2 allows "1% penetration or match rate". BPCER/FNMR must be ≤ 15% to PASS. That cap started unconstrained, was set at 20%, then cut to 15%, and is reviewed every six months. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Subsystem (PAD-only) tests report APCER, BPCER and non-response rates. Full-system tests report IAPMR together with FNMR/FMR. If systems with active liveness are tested, artefacts are adapted to mimic the requested behaviour ("movement, smile, blink"). iBeta stresses that results show conformance and are not a product certification. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- iBeta Level 3 now exists. It was reported as announced around June 2025, and Yoti was first to pass on 2026-01-27. Since then Incode (Mar 2026), Shufti (May 2026, "0 errors across iOS, Android") and Sumsub (Oct 2026, "zero spoofing errors") have passed. BixeLab also runs a Level 3 PAD test (Advance.ai, Oct 2026). Paravision passed a Level 3 assessment from Ingenium Biometrics (Aug 2025). — [Biometric Update search: iBeta Level 3](https://www.biometricupdate.com/?s=iBeta+Level+3)

**FIDO Alliance Biometric Requirements v4.1 (active until 31 March 2027; v5.0 rd02 dated 2026-09-01)**
- Document status and dates. — [FIDO biometric certification](https://fidoalliance.org/certification/biometric-component-certification/)
- FRR must be below 7% (BioLevel 1/2), or below 5% (1+/2+), at the upper bound of an 80% confidence interval. FAR must be below 1:100 (Level 1/1+) or below 1:10,000 (Level 2/2+), also at the 80% upper bound. — [FIDO Biometrics Requirements v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- IdV-Face, which matches a selfie to an ID document photo plus PAD: FRR 7% (5% at Level 2 with an NFC reference). FAR 1:100 at Level 1 and below 1:3000 at Level 2 ("for 100 subjects and calculation of rule of 1.51"). — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- PAD is measured as IAPAR (imposter attack presentation accept rate) per species. Each of 6 Level A species, and each of 8 Level B species, must stay under threshold: ≤ 15% for BioLevel 1, ≤ 7% for BioLevel 2, and ≤ 7% per species for IdV-Face, with total accepted attacks across species under 4%. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- Subject counts: 25 for FAR/FRR at BioLevel 1/2 and 245 at 1+/2+. IdV uses 25 at Level 1 and 100 at Level 2. PAD uses 15 subjects. An optional demographic evaluation uses 245 subjects and requires FRR below 6% in every age, gender and skin-tone group. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- PAD attempt protocol: one PAI per species per enrolled subject, then "10 impostor presentation attack transactions for each PAI". With 15 subjects that gives 150 transactions per species. The pass limits are 10 errors (7%) or 22 errors (15%). FAR testing uses 10 impostor transactions per enrolled user. A transaction "SHOULD NOT exceed 30 seconds". — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- Face PAI species. Level A: inkjet/laser printed photo, photo-lab print, photo shown on a phone/tablet/monitor (each device model is a separate species), cut-out photos (eyes, nose, mouth, face outline), and single-photo deepfake animation. Level B: video replay on a device, paper masks, and deepfakes built from multiple frames or video. Level C: silicone, ceramic or theatrical masks and 3D-printed faces. v4.1 "Added deepfake video testing to presentation attack Levels A and B." — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- Zero-error statistics: "Rule of 3 states the upper bound of the 95% confidence interval is 3/N". For an 80% bound, FIDO uses 1.61/N. Worked example: "1.61/25 leads to 6.4% FRR (<7%)". — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- "Injection attacks are out of scope for PAD testing". IdV vendors must document protections "from injection and replay attacks", and the lab verifies that documentation. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)

### Inferences
- ISO/IEC 30107-3 definitions. These are background knowledge, not fetched this session, because iso.org returned 403:
  - **APCER** = the share of attack presentations of one PAI species wrongly classified as bona fide. The standard reports it per species, and the headline figure is the worst species (max APCER).
  - **BPCER** = the share of bona fide presentations wrongly classified as attacks.
  - **APNRR / BPNRR** = the share of attack or bona fide attempts that produce no decision (timeouts, face not found).
  - **IAPMR** = the share of impostor attacks that are both accepted by PAD and matched by the recognizer (full-system "spoof success").
  - **ACER** = the mean of max APCER and BPCER. It appears in academic papers (OULU-NPU, CASIA-SURF), but ISO/IEC 30107-3 does not endorse it. Report it only next to APCER and BPCER, never on its own.
- How the metric families relate:
  - FMR/FNMR are algorithm-level comparison errors.
  - FAR/FRR are transaction-level and include retries and failure-to-acquire.
  - PAD errors are a separate axis: BPCER adds to the effective FRR, and APCER feeds IAPMR.
  - The end-to-end false reject seen by a user is roughly 1 − (1 − BPCER)(1 − FNMR), plus failure-to-acquire.
- HID's targets translated into this vocabulary:
  - "0.2% FAR / 0.6% FRR" is the matcher operating point.
  - "99.4% liveness accuracy" should be restated as "max APCER = X% per species at BPCER = Y%".
  - Accuracy hides the class balance. With 150 attacks and 50 bona fide attempts, a system that rejects everything scores 75% accuracy.
- Suggested pitch wording: "We followed an iBeta Level 1-style protocol: 6 PAI species under $30, 150 attacks alternated with 50 bona fide attempts, ISO 30107-3 metrics, FIDO rule-of-3 confidence bounds." This is accurate and defensible. Do not claim "iBeta certified/compliant".
- HID's "mask" scenario: paper masks are Level B (FIDO) and resin or latex masks are iBeta Level 2. Report masks separately as the stretch tier.

### Gaps
- I did not read the full ISO/IEC 30107-3:2023 text. Metric definitions above come from background knowledge. Verify the 2023 edition's exact naming (for example, whether it uses "IAPAR" or "IAPMR").
- iBeta Level 2 and Level 3 attempt counts and Level 3 artefact rules were not found.
- The FIDO Face Verification certification page URL returned 404. Its FIDO v5.0 changes (dated 2026-09-01) were not read.
- The NIST FATE PAD page was truncated, so I have no NIST findings.

## Q2. Building a small in-house test set in one day: sample sizes, confidence intervals, DET curves, thresholds

### Takeaway
One day is enough for a credible mini-protocol: about 10–15 volunteers, 6 attack species, roughly 10 attempts per species per subject, 3 lighting conditions, and a held-out split. Every rate should be reported with a confidence bound. With 0 errors in N trials the 95% upper bound is 3/N (the 80% bound is 1.61/N), so no hackathon sample can honestly back a "0.2% FAR" claim. Saying that openly reads as rigour.

### Cited Findings
- The FIDO PAD template is 15 subjects × 1 PAI per species × 10 attack transactions, which gives 150 per species. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- The iBeta Level 1 template is 150 attacks interleaved with 50 genuine attempts. Interleaving stops the system from "settling" into one class. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- Zero-error bounds: 3/N at 95% confidence and 1.61/N at 80% (ISO/IEC 19795-1 App. B.1.1). — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- FIDO caps a transaction at 30 s and uses 10 impostor transactions per enrolled user for FAR. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- AWS tells customers to choose liveness and face-match thresholds "after testing Liveness performance with various confidence score thresholds on their specific content". — [AWS Rekognition Face Liveness docs](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)

### Inferences
- **A one-day test plan:**
  - About 12 subjects, recruited from the team and nearby teams, with a deliberate spread of skin tones, glasses or no glasses, and beards.
  - Bona fide: 10 attempts per subject × 3 lighting conditions (office, backlit/window, dim) = 360 attempts.
  - Six attack species, mapped to HID's four scenarios:
    1. Laser/inkjet print
    2. Glossy photo print
    3. Phone screen photo
    4. Laptop/tablet replay video
    5. Cut-out or paper mask
    6. Deepfake/face-swap video on screen (FIDO Level A/B)
  - Optionally, a 3D-printed or latex mask as a "Level 2 stretch" species.
  - About 5 attempts per species per subject, which gives about 60 per species and 360 attacks in total.
  - Interleave bona fide and attack attempts.
- **Statistics:**
  - With 60 attacks per species and 0 errors, the 95% upper bound on APCER is 3/60 = 5%. With 150, it is 2%.
  - Matching HID's 0.6% FRR at 95% confidence with zero errors needs about 500 bona fide attempts. Matching 0.2% FAR needs about 1,500 impostor comparisons.
  - Impostor comparisons can be generated cheaply offline by cross-matching all subject pairs: 12 subjects give 132 ordered pairs × frames. Pad this out with a public face dataset (for example LFW) for FMR.
  - Use Wilson or Clopper-Pearson intervals when errors are nonzero.
- **Splits:** do not tune thresholds on the evaluation data. Choose the threshold on a dev split of subjects and report results on held-out subjects. Ideally hold out one unseen attack species ("leave-one-attack-out") to show generalisation.
- **Threshold selection:**
  - Plot the DET curve (APCER vs BPCER, or FMR vs FNMR, on normal-deviate or log axes) for each species.
  - Choose the operating point by policy. Examples: "BPCER ≤ 5% for kiosk throughput" or "APCER = 0 on the dev split", or report BPCER at APCER = 1%/5% (written BPCER@APCER=x%).
  - Show EER only as a summary.
- **Latency:** report p50/p95 end-to-end decision time over all bona fide attempts against HID's < 2 s target, and break it into capture, detection, PAD and matching.

### Gaps
- No primary source fetched on DET-curve conventions (ISO/IEC 19795-1) or Wilson/Clopper-Pearson. These are standard statistics, not verified this session.
- No authoritative guidance found on lighting or condition matrices for in-house PAD tests.

## Q3. HID Global's biometrics and liveness business and how to align the pitch

### Takeaway
HID is an ASSA ABLOY subsidiary built around physical access control. Its biometrics come from acquisitions (Lumidigm 2014, Crossmatch 2018). Its face products are the U.ARE.U Camera Identification System for kiosks (healthcare, Olea kiosks), which partners with Amazon Rekognition, plus airport and border work. The pitch should be framed as kiosk and door-reader access with cooperative users, varied lighting and throughput limits, not as remote KYC onboarding.

### Cited Findings
- HID is an independent subsidiary of ASSA ABLOY, acquired in 2000. It acquired Lumidigm (2014, biometric authentication) and Crossmatch (2018, biometric enrollment and identity devices), and IDmelon in 2025. — [Wikipedia: HID Global](https://en.wikipedia.org/wiki/HID_Global) (the article is flagged for promotional content)
- Jan 24, 2024: HID added face biometrics to Olea Kiosks using HID's "U.ARE.U Camera Identification System". — [Biometric Update search: HID face liveness](https://www.biometricupdate.com/?s=HID+Global+face+liveness)
- Jun 5, 2024: HID added Amazon Rekognition support to its biometric camera. — [Biometric Update](https://www.biometricupdate.com/?s=HID+Global+face+liveness)
- Mar 1, 2024: HID healthcare biometric kiosks launched, aimed at duplicate accounts and patient identification. Sep 2023: partnership with Certify Health. — [Biometric Update](https://www.biometricupdate.com/?s=HID+Global+face+liveness)
- HID's 2024 State of Physical Access Control report found 39% of businesses use biometrics for physical access, up from 30% two years earlier. — [Biometric Update](https://www.biometricupdate.com/?s=HID+Global+face+liveness)
- Oct 25, 2026: "HID makes the case for airport biometrics built for real-world conditions". The article opens with a traveller rejected at an automated passport gate. Jan 2025: HID's Biometrics BU head, Vito Fabbrizio, wrote on face recognition trends for borders and travel. — [Biometric Update](https://www.biometricupdate.com/?s=HID+Global+face+liveness)
- AWS Face Liveness, which HID's camera integrates with, returns a 0–100 liveness score, a reference image and up to 4 audit images. It offers FaceMovementAndLightChallenge (most accurate) or FaceMovementChallenge (faster). — [AWS docs](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)

### Inferences
- **Fit with HID:**
  - Physical access means a fixed camera and a cooperative, repeat user. Throughput and BPCER (rejecting employees at the door) matter as much as APCER.
  - HID's own 2026 messaging stresses "real-world conditions". Lighting and fairness robustness therefore speaks directly to the sponsor.
- **Product framing:**
  - "Drop-in liveness for U.ARE.U-style kiosk cameras and access readers."
  - Output a decision plus audit images and a reason code, which mirrors the AWS response shape HID already integrates.
  - Credential fusion: face plus HID mobile ID or Seos card as a second factor for risk step-up.
- Background knowledge, not verified this session: HID Amico (face-recognition access reader), HID Signo readers, U.are.U fingerprint readers, Lumidigm multispectral fingerprint liveness. Check names on hidglobal.com before putting them on slides.

### Gaps
- hidglobal.com returned 403, so HID product pages (Amico, Signo, U.ARE.U Camera specs, any iBeta results for HID face liveness) were not verified.
- No source found on whether HID's face camera has its own iBeta PAD confirmation.
- Bio-key is a separate company, not an HID product. Its relationship to HID was not researched.

## Q4. Commercial liveness techniques to borrow from

### Takeaway
The industry leaders combine (a) passive single-frame or short-video PAD, (b) an active or semi-active challenge, often screen-emitted light that cannot be predicted ahead of time, and (c) defences against injection and replay. AWS's colour-light challenge and the "one-time" illumination idea behind iProov are the most useful patterns a kiosk prototype can copy.

### Cited Findings
- AWS Face Liveness has the user move their face into an on-screen oval, then the SDK shows "a sequence of colored lights" before streaming the video to the cloud. AWS says the light challenge "remains the best setting to maximize accuracy". It returns feedback codes for low-confidence sessions so the user can be told how to retry. AWS advises that owners "implement controls to secure the device the video stream is sent from" and combine liveness with other signals (IP geolocation, OTP) for "a risk-based decision". — [AWS docs](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- Since 2025–2026 many vendors have passed iBeta Level 3 or BixeLab Level 3 PAD plus IAD (Yoti, Incode, Shufti, Sumsub, HyperVerge, Advance.ai, Idemia, Innovatrics). — [Biometric Update: iBeta Level 3](https://www.biometricupdate.com/?s=iBeta+Level+3); [Biometric Update: CEN TS 18099](https://www.biometricupdate.com/?s=CEN+TS+18099)

### Inferences (background knowledge, not verified this session)
- **iProov Flashmark:** the screen flashes a random colour sequence, and the reflected colours on the face form a one-time "biometric" that a replay or injection cannot reproduce in real time.
- **FaceTec:** 3D face map built from close/far perspective distortion while the user moves the phone.
- **Apple Face ID:** IR dot projector depth plus IR flood, and neural attention checks, on dedicated hardware.
- **ID R&D IDLive Face:** passive single-image PAD with no user interaction.
- **Paravision:** passive liveness plus deepfake and injection detection.
- **A hackathon version of the flash idea:** randomise the kiosk screen colour per session, then check that the colour change on the face skin matches the emitted sequence (correlation over time), with a timing check. This combines challenge-response, replay resistance and injection resistance, and needs no special hardware.

### Gaps
- iProov, FaceTec, Paravision and ID R&D pages could not be fetched (404 or failure). Their technique descriptions above are not source-verified.

## Q5. Emerging threat: deepfake and injection attacks, and how to detect them

### Takeaway
Injection attacks (virtual cameras, emulators, streaming deepfakes) bypass the sensor. ISO 30107-3 PAD testing explicitly excludes them, and they are now tested separately against CEN/TS 18099, with labs such as BixeLab and CLR Labs certifying vendors throughout 2026. Showing even a basic IAD layer would be a strong Innovation point.

### Cited Findings
- FIDO: "Injection attacks are out of scope for PAD testing". IdV vendors must document protections against injection and replay attacks. FIDO v4.1 added deepfake video as a PAD species (Levels A/B). — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- CEN/TS 18099 covers biometric injection attack detection (IAD), which is separate from presentation attacks. One article argues injection attacks can be stopped "but not with liveness detection or deepfake detection". The EAB is developing formal standards (Jul 2026). — [Biometric Update: CEN TS 18099](https://www.biometricupdate.com/?s=CEN+TS+18099)
- 2026 IAD certifications:
  - Innovatrics: CLR Labs IAD, High level (Nov 2, 2026)
  - HyperVerge: BixeLab IAD plus Level 3 PAD (Oct 28)
  - Idemia PS: BixeLab IAD, blocked all bypass attempts (Oct 6)
  - ShareID: three PAD/IAD standards (Sep 23)
  - EU QTSPs must complete biometric attack testing under eIDAS by end-2026, and ETSI TS 119 461 raises the bar for remote proofing.
  - Paravision proposed a Kantara injection-attack discussion group (Oct 26, 2026).
  - [Biometric Update](https://www.biometricupdate.com/?s=CEN+TS+18099)
- Low-skill attackers use face-swap apps such as SwapFace, DeepFaceLive and Swapstream and inject them into the camera feed. iProov reported a 704% rise in face-swap attacks in H1 2023. — [Wikipedia: Liveness test](https://en.wikipedia.org/wiki/Liveness_test)

### Inferences
- **Feasible IAD for a kiosk or web prototype:**
  1. Device-integrity check: enumerate camera devices and flag known virtual-camera names (OBS Virtual Camera, ManyCam, DroidCam, and others) or device-label anomalies.
  2. Stream-forensics signals: frame-timing jitter, unchanging EXIF-like resolution and FPS profile, no sensor noise.
  3. Challenge-response bound to time: the random screen-colour flash or a random head-turn direction, verified within a latency window. A pre-recorded or slow generated stream fails this.
  4. Signed capture: sign frames on the kiosk device and verify on the server.
- On a fixed HID kiosk, the camera is physically wired, so injection risk is lower than for mobile or web. This point is worth making to show threat-model judgement.
- **Demo idea:** run DeepFaceLive or OBS as a virtual camera live on stage and show the system flag "injection suspected" separately from "presentation attack".

### Gaps
- I did not read the CEN/TS 18099 text, so I have no attack-level taxonomy or metrics.
- I could not verify the status of ISO/IEC 25456 (the ISO version of 18099).

## Q6. Differentiation ideas mapped to the judging criteria

### Takeaway
The highest-leverage differentiators are:
1. An honest, standards-based evaluation report with per-species APCER, confidence bounds and DET curves (Technical 25%).
2. Risk-adaptive step-up: passive PAD first, then a light or head-turn challenge only when the score is uncertain (Problem-Solution Fit and Usability).
3. A visible injection-attack layer plus a deepfake species (Innovation).
4. A live attack-simulation dashboard with explainability heatmaps (Presentation).
5. A fairness and lighting breakdown that mirrors FIDO's demographic test (Problem-Solution Fit, and HID's "real-world conditions" theme).

### Cited Findings
- AWS recommends combining liveness with other signals for "a risk-based decision", and offers a faster versus more accurate challenge mode. This is the industry precedent for adaptive step-up. — [AWS docs](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- FIDO's optional demographic evaluation requires FRR below 6% in every age, gender and skin-tone group (245 subjects). This is the precedent for per-group fairness reporting. — [FIDO v4.1](https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v4.1-fd-20250106.html)
- AWS returns audit images and feedback codes, the precedent for explainable, auditable decisions and user retry guidance. — [AWS docs](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- iBeta caps BPCER at 15% because usability matters. iBeta suspends testing if bona fide users can't be recognised. — [iBeta](https://www.ibeta.com/iso-30107-3-presentation-attack-detection-confirmation-letters/)
- HID's 2026 airport messaging centres on biometrics "built for real-world conditions" and on avoiding false rejects at gates. — [Biometric Update](https://www.biometricupdate.com/?s=HID+Global+face+liveness)

### Inferences
1. **Risk-adaptive step-up:**
   - Passive PAD and matching run in about 300 ms.
   - If the PAD score falls in a gray zone, or the context is high-risk (after hours, restricted zone), trigger a random screen-colour flash or head-turn challenge.
   - If still uncertain, fall back to an HID card or mobile credential.
   - This keeps BPCER low for most users while pushing APCER toward 0.
2. **Multi-signal fusion:**
   - Texture/frequency CNN (print, moiré)
   - Depth from monocular estimation, or a stereo/IR camera if available
   - rPPG pulse signal over 2–3 s
   - Specular and colour response to the flash
   - Blink and micro-motion
   - Show the fused score and each signal's contribution.
3. **Explainability:** Grad-CAM heatmaps (moiré on the screen edge, paper border), plus a reason code ("screen moiré detected", "no pulse signal", "flash response mismatch"). These help security operators and judges alike.
4. **Attack-simulation dashboard:**
   - A live confusion matrix for each species, filled in during the demo.
   - DET curves.
   - p50/p95 latency compared with HID's 2 s target.
   - A "HID target vs ours (with 95% upper bound)" table.
5. **Fairness and conditions:** BPCER and FNMR for each lighting condition and skin-tone group (Monk scale), modelled on FIDO's per-group FRR check.
6. **Privacy:**
   - Templates and PAD run on the device or kiosk edge.
   - Store only encrypted embeddings, never images.
   - Templates can be revoked or cancelled.
   - Audit images are kept only for rejected attacks, with a retention limit.
   - Mention GDPR or BIPA compliance briefly.
7. **Injection detection** as a separately reported layer (see Q5), to show awareness of CEN/TS 18099.
8. **Honest reporting:**
   - Restate HID's "99.4% accuracy" as ISO metrics.
   - Show the rule-of-3 bound ("0 errors / 150 attacks gives APCER < 2% at 95% confidence").
   - Explain why the 0.2% FAR claim needs about 1,500 or more impostor trials.
   - Judges from HID will recognise this vocabulary.

### Gaps
- No published data was found on which differentiators hackathon judges or HID reward most. The weighting above is inferred from the rubric.
- I found no source on rPPG or flash-response accuracy for kiosk-distance capture. Feasibility is not verified.
