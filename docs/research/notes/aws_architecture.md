> Non-normative research notes (pre-build). Where they differ from docs/*.md, the docs win.

# AWS Services and Deployment Architecture for a <2 s Face Liveness + Face Authentication Kiosk (Hackathon, ap-south-1)

Research date: 2026-11-14. All sources are AWS primary docs fetched on this date unless noted. No WebSearch tool was available, so this rests on direct fetches of AWS doc and pricing pages. Several pages (Rekognition FAQ, Workshop Studio docs, DPDP Rules PDF/PIB release, the 2025 FaceMovementChallenge announcement) returned 404/403 or empty content. Those items are listed under Gaps.

## 1. Amazon Rekognition Face Liveness: mechanics, regions, pricing, spoof coverage, fit for a <2 s budget

### Takeaway
Face Liveness is a managed, iBeta PAD Level 1/2-tested, video-selfie challenge. The flow is: backend `CreateFaceLivenessSession`, then the browser's Amplify `FaceLivenessDetector` streams video over WebSocket, then backend `GetFaceLivenessSessionResults` returns a 0-100 confidence, a reference image and 0-4 audit images. It runs in ap-south-1 (Mumbai) and costs about $0.015 per check (us-east-1 first tier). The user has to put their face in an oval and hold still, and the default mode also flashes a colour sequence. AWS publishes no duration figure, but the interaction plainly takes several seconds, so a strict "<2 s from face-in-frame to decision" budget is unrealistic with Face Liveness on the critical path. Treat it as a step-up or enrollment check, or redefine the 2 s budget to start after capture.

### Cited Findings
- **Flow and APIs.** Three APIs are involved. `CreateFaceLivenessSession` starts a session and returns a SessionId; it also lets you set ChallengePreference. `StartFaceLivenessSession` is called by the Amplify FaceLivenessDetector and opens an event stream. `GetFaceLivenessSessionResults` returns the confidence score, reference image, audit images, SDK type and, for low-confidence sessions, feedback codes. — [AWS Rekognition DG: Detecting face liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- **Two challenge types.** With `FaceMovementAndLightChallenge` (the default), the face moves into an oval and the SDK shows a sequence of coloured lights. `FaceMovementChallenge` uses the oval only, with no lights. AWS says FaceMovementAndLight "remains the best setting to maximize accuracy" and FaceMovement "allows customers to prioritize faster speed of liveness checks over accuracy." — [Detecting face liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html); [CreateFaceLivenessSession API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_CreateFaceLivenessSession.html)
- **Outputs.** You get a confidence score from 0 to 100, a "high-quality" reference image for CompareFaces or SearchFacesByImage, up to 4 audit images, and feedback codes. — [Detecting face liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- **CreateFaceLivenessSession parameters:**
  - `ClientRequestToken` (idempotency).
  - `KmsKeyId`, which encrypts audit and reference images.
  - `Settings.OutputConfig`, an S3 bucket and prefix for the images. Without it, raw bytes are returned instead.
  - `AuditImagesLimit`, from 0 to 4 with a default of 0. It is "best effort and based on the duration of the selfie-video."
  - `ChallengePreferences`.
  - A SessionId is single-use and "expires 3 minutes after it's sent, making all Liveness data associated with the session ... unavailable."
  - Source: [CreateFaceLivenessSession API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_CreateFaceLivenessSession.html)
- **GetFaceLivenessSessionResults.** Status is one of `CREATED | IN_PROGRESS | SUCCEEDED | FAILED | EXPIRED`. Confidence is a float from 0 to 100. The response also includes ReferenceImage (bytes or S3 object, with bounding box), AuditImages, Challenge {Type, Version}, Feedback (up to 10 codes, only when SUCCEEDED) and Metadata.SDKType. If no reference image comes back, AWS recommends retrying the check. — [GetFaceLivenessSessionResults API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_GetFaceLivenessSessionResults.html)
- **Amplify UI React component (`@aws-amplify/ui-react-liveness` + `aws-amplify`):**
  - Required props are `sessionId`, `region` (it must match the CreateFaceLivenessSession region) and `onAnalysisComplete`. Optional props include `onError`, `onUserCancel`, `disableStartScreen`, `components` and `displayText`.
  - The component uses a Cognito Identity Pool "for the sole purpose of signing requests to Rekognition." Unauthenticated guest identities are supported, and the role needs `rekognition:StartFaceLivenessSession`.
  - `FaceLivenessDetectorCore` accepts a custom `credentialProvider`. Credentials are fetched once, "with no token refresh."
  - It ships TensorFlow.js WASM plus BlazeFace for on-device face detection.
  - Error states include `CAMERA_FRAMERATE_ERROR`, `MULTIPLE_FACES_ERROR`, `FACE_DISTANCE_ERROR`, `CONNECTION_TIMEOUT`, `TIMEOUT` and `FRESHNESS_TIMEOUT`.
  - Sessions are single-use, so retries need a new session.
  - The docs warn: make authorization decisions in the backend, not from the client-side `isLive`.
  - Source: [Amplify UI Liveness docs](https://ui.docs.amplify.aws/react/connected-components/liveness)
- **Regions.** ap-south-1 Mumbai has the standard Rekognition endpoint and also the streaming endpoint `streaming-rekognition.ap-south-1.amazonaws.com` (WSS), which Liveness needs. Other streaming regions are us-east-1, us-west-2, ap-northeast-1, eu-west-1, sa-east-1, ap-southeast-5 and ap-southeast-7. The Face Liveness quota table lists the same 8 regions, Mumbai included. Singapore (ap-southeast-1) is NOT in that list. — [Rekognition endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/rekognition.html)
- **Quotas in Mumbai.** Face Liveness APIs are limited to 5 TPS (versus 25 TPS in us-east-1/us-west-2). Concurrent liveness sessions are limited to 15 (versus 75). AWS sizes concurrency as "estimated session length × TPS (Ex. 10 seconds x 5 TPS = 50)". This example implies AWS plans for sessions of roughly 10 s. — [Rekognition endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/rekognition.html)
- **Pricing (us-east-1 tiers taken from the page's worked examples; the region tables did not render).** The first 500K checks per month cost $0.015 each, the next 2.5M cost $0.0125 and above 3M cost $0.010. No free tier for Liveness is mentioned. New customers get up to $200 in credits from 15 Jul 2025. — [Rekognition pricing](https://aws.amazon.com/rekognition/pricing/)
- **Spoof types.** The design target is low scores for "2D photos, 3D full-face masks, digital photos or videos displayed on a device screen, and pre-recorded videos." It is "designed to detect presentation and digital injection attacks," and injection here includes "pre-recorded or deepfake videos" that bypass the camera. — [AWS AI Service Card: Face Liveness](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)
- **iBeta PAD (ISO/IEC 30107-3) results:**
  - Level 1: 6 attack types (printed photos, 3D masks, photos on phones, videos on laptops). 900 attacks gave 100% TRR and 300 genuine attempts gave 100% TAR, both at threshold 50.
  - Level 2: silicone, latex, 3D-contoured and 3D-printed masks plus 3D animation software. 750 attacks gave 100% TRR and 250 genuine attempts gave 100% TAR, at threshold 50.
  - Note that the service card is "current as of November 27, 2023" (older info).
  - Source: [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)
- **Threshold guidance.** A threshold of 50-60 suits presentation attacks and some injection attacks. A threshold of 80-90 targets "sophisticated digital injection attacks, such as deep fake or pre-recorded videos." Indoor, well-lit conditions support higher thresholds, while outdoor or bright sun increases false rejects. — [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)
- **Device requirements:**
  - Front camera, ≥60 Hz screen, ≥4" screen, ≥100 kbps bandwidth.
  - Colour camera, not virtual-camera software, ≥15 fps, ≥320×240.
  - Desktop webcams must be mounted on top of the screen.
  - Browsers: Chrome, Firefox, Safari, Edge.
  - Source: [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)
- **Operational recommendations:**
  - Use even lighting and maximum screen brightness on web.
  - "Do not send or display the liveness check score on the user application. Only send a pass or fail signal."
  - Rate-limit to 5 failed checks per 3 minutes per device, then time out for 30-60 minutes.
  - Provide an alternative path for photosensitive users.
  - Source: [Recommendations for Usage of Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/recommendations-liveness.html)

### Inferences
- **Duration.** The user has to align their face to an oval, "hold still", and in the default mode watch a colour sequence, then the video is streamed and analysed. AWS's own concurrency example assumes a ~10 s session. A realistic kiosk interaction is therefore probably about 3-8 s (FaceMovementChallenge sits at the shorter end), plus about 0.3-1 s of backend round trips. This estimate is not an AWS-published figure.
- **Meeting the 2 s requirement.** For the hackathon, either (a) define the 2 s SLA as "capture complete → decision", or (b) run a fast on-device passive check plus a cloud 1:N face search on the main path, and invoke Face Liveness only for the REQUEST VERIFICATION band.
- **Kiosk lighting.** The colour-light challenge depends on the screen lighting up the face. A kiosk in a bright hall may push you toward FaceMovementChallenge or lower thresholds.
- **Mumbai quotas.** 5 TPS and 15 concurrent sessions are plenty for a hackathon demo, but a large judging crowd hitting the system at once could get throttled.

### Gaps
- No AWS-published median or p95 duration for a liveness session (either challenge type) was found. The Rekognition FAQ and the 2025 challenge-setting announcement URLs returned 404 or no content.
- Mumbai-specific Liveness and Image API prices are not confirmed, because the region pricing tables did not render. Verify with the [AWS Pricing Calculator](https://calculator.aws/#/createCalculator/Rekognition).
- How long results stay retrievable after completion, beyond the 3-minute SessionId expiry, is unclear.

## 2. Rekognition face matching: CompareFaces, IndexFaces/SearchFacesByImage, collections, user vectors, thresholds, latency

### Takeaway
For a kiosk "who is this?" decision, use one collection with one user vector per enrollee: `IndexFaces` several images, `CreateUser`, then `AssociateFaces`. Authenticate with `SearchUsersByImage` (1:N, a single call). For a claimed identity (badge or QR), use `CompareFaces` against the stored enrollment image (1:1). Each of these is a single synchronous call priced at $0.001 per image (Group 1, first 1M). AWS publishes no latency SLA. Mumbai TPS defaults are low: 5 TPS for search and index, 25 TPS for CompareFaces.

### Cited Findings
- **CompareFaces.** It compares the largest face in the source image against up to 15 faces in the target image. Only the source image is billed. AWS suggests it for "near real-time" verification but gives no latency numbers. — [Rekognition FAQ](https://aws.amazon.com/rekognition/faqs/)
- **SearchUsersByImage.** It detects the largest face and searches the collection's UserIDs. `UserMatchThreshold` defaults to 80 (range 0-100), `MaxUsers` ranges from 1 to 500, and `QualityFilter` is one of NONE (default), AUTO, LOW, MEDIUM or HIGH. It returns `UserMatches[{Similarity, User{UserId, UserStatus}}]`, `SearchedFace` and `UnsearchedFaces`. The S3 bucket must be in the same region. — [SearchUsersByImage API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_SearchUsersByImage.html)
- **User vectors.** A face associated with a user vector can't be deleted directly; you must DisassociateFaces or DeleteUser first. User search is not supported for video. — [Rekognition FAQ](https://aws.amazon.com/rekognition/faqs/)
- **Fixed limits:**
  - 20M face vectors and 10M user vectors (default) per collection. Search returns at most 4096 matches.
  - Images: 5 MB as bytes, 15 MB from S3, JPEG or PNG, minimum 80 px per side.
  - A face must be ≥40×40 px in a 1920×1080 image.
  - Source: [Rekognition guidelines and quotas](https://docs.aws.amazon.com/rekognition/latest/dg/limits.html)
- **Default TPS in ap-south-1:**
  - IndexFaces, SearchFaces, SearchFacesByImage, SearchUsers and SearchUsersByImage: 5 TPS each (versus 50 in us-east-1/us-west-2/eu-west-1).
  - CompareFaces and DetectFaces: 25 TPS (versus 100).
  - AssociateFaces/DisassociateFaces: 5. CreateCollection, CreateUser and the other control-plane calls: 5.
  - Source: [Rekognition endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/rekognition.html)
- **Throttling.** AWS advises retries with exponential backoff and jitter. `ProvisionedThroughputExceededException` and `ThrottlingException` are both retryable. For TPS sizing, AWS assumes response windows of "5 - 15 seconds" and treats "5 seconds [as] the minimum." That is a capacity-planning convention, not a latency figure. — [Rekognition guidelines and quotas](https://docs.aws.amazon.com/rekognition/latest/dg/limits.html)
- **Pricing.** CompareFaces, IndexFaces and SearchFacesByImage are Group 1: $0.0010 per image for the first 1M per month, then $0.0008, $0.0006 and $0.0004. Face or user metadata storage costs $0.00001 per object per month. The 12-month free tier includes 1,000 Group 1 images per month and 1,000 face plus 1,000 user vectors. — [Rekognition pricing](https://aws.amazon.com/rekognition/pricing/)
- **Example flow.** The service card suggests running Liveness, then passing the reference image to CompareFaces against a previously stored image, for step-up authentication. — [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)

### Inferences
- **Suggested decision bands.** These are not AWS-specified; tune them on test data.
  - ALLOW: liveness pass and SearchUsers similarity ≥ about 95-99.
  - REQUEST VERIFICATION: similarity about 80-95, or a borderline liveness score. Respond with step-up (Face Liveness session or OTP).
  - DENY: no match, or a liveness fail.
  - AWS's general face-matching guidance favours high thresholds (99) for sensitive uses, but I could not fetch that specific doc page in this session.
- **Latency.** Single image-API calls are commonly a few hundred ms from in-region clients, which should fit the 2 s budget. Send a compressed JPEG (≤ about 200 KB, face ≥ about 200 px) as bytes to avoid an S3 round trip. This is unverified, so measure it on the day.

### Gaps
- No AWS-published p50/p95 latency for CompareFaces or SearchUsersByImage.
- Not verified in a fetched doc: the AssociateFaces `UserMatchThreshold` default (I believe 75) and the maximum of 100 faces per user. The fetch of the user-vectors DG page returned empty content.

## 3. Hosting custom models: SageMaker vs Lambda vs EC2 vs Fargate, plus API Gateway, S3, DynamoDB, Cognito, OTP and CloudWatch

### Takeaway
For a one-day build, the lowest-risk path is the managed services: Rekognition, Lambda (Python 3.12+ with SnapStart, or provisioned concurrency) and API Gateway. If you bring your own anti-spoof or embedding model (ONNX):
- A small CPU model fits a Lambda container image or a warm SageMaker real-time endpoint.
- SageMaker Serverless Inference has no GPUs and has cold starts.
- A single EC2 or real-time endpoint kept warm gives the most predictable latency.

SMS OTP to Indian numbers needs TRAI DLT registration (PAN, TAN, GSTIN, CIN). That is infeasible in a day, so use email OTP (SES or Cognito) or show the OTP on screen for the demo.

### Cited Findings
- **Lambda SnapStart:**
  - Supported runtimes are Java 11+, Python 3.12+ and .NET 8+, for both ZIP and container images. Node.js and OS-only runtimes are not supported.
  - It is not compatible with provisioned concurrency, EFS, or ephemeral storage >512 MB, and it works only on published versions and aliases.
  - It is available in all commercial regions except NZ and Taipei, so ap-south-1 is covered.
  - It reduces init "from several seconds to as low as sub-second". Provisioned concurrency keeps functions "ready to respond in double-digit milliseconds" for strict cold-start needs.
  - Python SnapStart incurs caching (minimum 3 h) and restore charges.
  - Source: [Lambda SnapStart docs](https://docs.aws.amazon.com/lambda/latest/dg/snapstart.html)
- **SageMaker Serverless Inference:**
  - Available in Asia Pacific (Mumbai).
  - Memory is 1-6 GB, with 5 GB ephemeral disk and a 10 GB container image limit.
  - "Ideal for workloads which have idle periods ... and can tolerate cold starts". Cold start depends on model size and container start-up. Provisioned Concurrency keeps it warm, responding "within milliseconds".
  - It does not support GPUs, VPC configuration, multi-model endpoints, data capture or Model Monitor.
  - Mumbai account-wide concurrency is 500, with a per-endpoint maximum of 200.
  - Source: [SageMaker Serverless Inference docs](https://docs.aws.amazon.com/sagemaker/latest/dg/serverless-endpoints.html)
- **Amplify FaceLivenessDetector credentials.** The component needs a Cognito Identity Pool (unauthenticated access allowed) or a custom credential provider. Your backend must create sessions and fetch results. — [Amplify UI Liveness](https://ui.docs.amplify.aws/react/connected-components/liveness)
- **SMS to India (AWS End User Messaging SMS):**
  - India supports short codes. Long codes are inbound-only. Sender IDs are "Registration required".
  - Local routes require registering the use case and templates with TRAI on a DLT portal, which yields an Entity ID and Template ID.
  - Registration needs PAN, TAN, GSTIN, CIN and a letter of authorization.
  - Source: [Supported countries](https://docs.aws.amazon.com/sms-voice/latest/userguide/phone-numbers-sms-by-country.html); [India sender ID registration](https://docs.aws.amazon.com/sms-voice/latest/userguide/registrations-sms-senderid-india.md)
- **SMS reliability.** SMS goes through a single carrier partner per country. AWS recommends redundant channels such as WhatsApp, push, voice or SES email. — [Supported countries](https://docs.aws.amazon.com/sms-voice/latest/userguide/phone-numbers-sms-by-country.html)

### Inferences
- **Option comparison** (my synthesis; the latency figures are typical expectations, not AWS-published):

| Option | Cold start | Warm latency (small CPU ONNX, ~5-30 MB) | Day-1 effort | Notes |
|---|---|---|---|---|
| Rekognition APIs only | none | single call, sub-second expected | lowest | No model ops. Mumbai TPS 5/25 |
| Lambda container image + onnxruntime | seconds (image pull + model load); mitigate with SnapStart (Py 3.12+) or provisioned concurrency | tens to low hundreds of ms on 2-3 GB memory | low-medium | 10 GB image limit; no GPU |
| SageMaker real-time endpoint (ml.c5/ml.g4dn) | none once InService (deploy takes minutes) | low tens of ms on GPU | medium | Instance-hour billing; sandbox may block GPU types |
| SageMaker Serverless | yes, unless provisioned concurrency is set | similar to Lambda | medium | No GPU |
| EC2 (c6i/c7g CPU or g4dn GPU) + FastAPI | none | lowest and most predictable | medium (AMI, SG, TLS) | g4dn often blocked in sandboxes or needs a quota |
| ECS Fargate | task start roughly 30-60 s; keep 1 task warm | like EC2 CPU (no GPU on Fargate) | medium-high | ALB required |

- **Glue services.** Use API Gateway HTTP API (lower overhead than REST) with Lambda for `/session`, `/result` and `/authenticate`, or an API Gateway WebSocket for push. DynamoDB on-demand stores user records (userId, Rekognition UserId, status, enrolledAt, consent flag), with TTL for retention. S3 with SSE-KMS holds enrollment and audit images and is set as the Liveness OutputConfig. Cognito Identity Pool provides kiosk credentials. CloudWatch EMF metrics should track the decision-latency histogram, similarity and liveness distributions, and throttles.
- **Keep the Rekognition region the same everywhere.** Lambda, S3 and the collection must all be in the same region (the S3 same-region rule is documented for SearchUsersByImage). Use ap-south-1 for everything to minimise RTT from Bangalore.

### Gaps
- No primary-source numbers for Lambda container cold start with onnxruntime, or for API Gateway overhead in ap-south-1.
- Not fetched: SageMaker real-time instance prices in Mumbai, EC2 g4dn availability in ap-south-1, End User Messaging SMS sandbox limits (new accounts start in SMS sandbox with verified destinations only, per my prior knowledge, unverified here), and Amazon Pinpoint end-of-support status (my prior knowledge is that Pinpoint engagement features end on 30 Oct 2026 and are migrating to End User Messaging/Connect; verify).

## 4. Security and privacy: encrypting biometrics, KMS, retention, GDPR and India DPDP Act 2023

### Takeaway
Encrypt every biometric artifact with a customer-managed KMS key. That means Liveness reference and audit images (`KmsKeyId` plus an S3 OutputConfig with SSE-KMS), enrollment images in S3, and DynamoDB tables. Store Rekognition face/user vectors rather than raw images where possible. Collect explicit consent and show a notice at the kiosk. Set short retention with automated deletion (S3 lifecycle, DynamoDB TTL, DeleteUser/DeleteFaces), and opt out of AWS AI service training via an AWS Organizations policy where possible.

### Cited Findings
- `CreateFaceLivenessSession.KmsKeyId` is "used to encrypt audit images and reference images". OutputConfig writes them to your S3 bucket. — [CreateFaceLivenessSession API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_CreateFaceLivenessSession.html)
- Liveness data becomes unavailable 3 minutes after the session is sent. Long-term storage is therefore only what you persist yourself. — [CreateFaceLivenessSession API](https://docs.aws.amazon.com/rekognition/latest/APIReference/API_CreateFaceLivenessSession.html)
- Inputs and outputs are never shared between customers. Customers can opt out of training on customer content via AWS Organizations AI services opt-out policies. — [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html); [Rekognition FAQ](https://aws.amazon.com/rekognition/faqs/)
- "You are responsible for providing legally adequate privacy notices to, and obtaining any necessary consent from, your End Users." AWS also recommends an alternative verification path. — [Recommendations for Usage of Face Liveness](https://docs.aws.amazon.com/rekognition/latest/dg/recommendations-liveness.html)
- AWS recommends human review for high-risk decisions and consistent policies across demographic groups. It also recommends disclosing ML and face-analysis use to end users. — [AI Service Card](https://docs.aws.amazon.com/ai/responsible-ai/rekognition-face-liveness/overview.html)

### Inferences
- **GDPR.** Biometric data used for unique identification is special-category data under Art. 9, so it needs explicit consent or another Art. 9(2) basis, a DPIA, data minimisation and storage limitation. This comes from general knowledge; I fetched no source this session.
- **DPDP Act 2023 (India).** The Act has no separate "sensitive" category. Biometric data is personal data, so you need notice plus free, specific, informed, unambiguous consent, purpose limitation, erasure when the purpose ends, reasonable security safeguards, and breach notification to the Data Protection Board and affected principals. The DPDP Rules were reported as notified in November 2025 with phased commencement (about 12-18 months for most obligations). I could not fetch the MeitY or PIB primary text (403), so treat these details as unverified.
- **Hackathon hygiene.**
  - Use synthetic or consenting team-member faces only, and put a consent checkbox on the enrollment screen.
  - Set S3 lifecycle expiry at 1-7 days and DynamoDB TTL.
  - Run a teardown script that calls DeleteCollection and empties the buckets.
  - Never log images or base64 to CloudWatch.
  - Keep data in ap-south-1. India data residency is not mandated by DPDP, but it is good optics.

### Gaps
- Primary text of the DPDP Rules 2025 (dates, breach timelines, retention clauses) was not retrieved, because MeitY and PIB returned 403.
- I did not fetch the Rekognition security pages that cover at-rest encryption of collections and face vectors.

## 5. Hybrid on-device/browser fast path plus cloud verification, and keeping end-to-end under 2 s

### Takeaway
A sub-2 s ALLOW path is achievable only if the cloud step is a single in-region image call. The browser handles face detection, quality and passive liveness gating, then sends one JPEG to API Gateway, which invokes Lambda, which calls `SearchUsersByImage` in ap-south-1. Face Liveness (the interactive challenge) belongs on the REQUEST VERIFICATION path or at enrollment, where a few extra seconds are acceptable.

### Cited Findings
- The Amplify FaceLivenessDetector itself runs on-device face detection (TensorFlow.js WASM plus BlazeFace) before streaming, so in-browser detection is AWS's own pattern. — [Amplify UI Liveness](https://ui.docs.amplify.aws/react/connected-components/liveness)
- The reference image from Liveness is intended for direct use with CompareFaces or SearchFacesByImage. — [Detecting face liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- AWS states that FaceMovementChallenge trades accuracy for speed. Customers should combine liveness with other factors such as OTPs and geolocation, and should secure the device the video is streamed from. — [Detecting face liveness](https://docs.aws.amazon.com/rekognition/latest/dg/face-liveness.html)
- The client should only ever receive pass or fail. Never send the score to the client. — [Recommendations](https://docs.aws.amazon.com/rekognition/latest/dg/recommendations-liveness.html)

### Inferences
**Proposed reference architecture (all ap-south-1).**

```
Kiosk browser (React + Vite)
 ├─ getUserMedia → MediaPipe/BlazeFace face detect + quality (blur, pose, size)
 ├─ optional on-device passive anti-spoof ONNX (onnxruntime-web, WebGPU/WASM) → spoofScore
 ├─ capture best frame → JPEG ~640px, ~100-200 KB
 └─ POST /authenticate (HTTPS, API Gateway HTTP API, kiosk auth via Cognito / API key)
        │
        ▼
  Lambda "authenticate" (Python 3.12, SnapStart or provisioned concurrency=1, 1-2 GB)
   ├─ rekognition.search_users_by_image(CollectionId, Bytes, UserMatchThreshold=80, MaxUsers=1, QualityFilter=AUTO)
   ├─ (optional) DetectFaces quality / call custom anti-spoof model (SageMaker RT endpoint or same Lambda ONNX)
   ├─ DynamoDB GetItem(user) → status/role
   ├─ decision: ALLOW / REQUEST_VERIFICATION / DENY  (+ CloudWatch EMF latency metric)
   └─ return {decision, stepUp: "liveness"|"otp"|null}
        │
 REQUEST_VERIFICATION →
   POST /liveness/session → Lambda → CreateFaceLivenessSession(KmsKeyId, OutputConfig S3, ChallengePreferences=FaceMovementChallenge?, AuditImagesLimit=1)
   Browser <FaceLivenessDetector sessionId region="ap-south-1"> (Cognito Identity Pool unauth role: rekognition:StartFaceLivenessSession)
   onAnalysisComplete → GET /liveness/result → Lambda → GetFaceLivenessSessionResults → Confidence ≥ T && CompareFaces(reference image vs enrolled) ≥ S → ALLOW else DENY / OTP (SES email)

Enrollment (admin page): Liveness check → reference image → IndexFaces (ExternalImageId=userId) ×3 → CreateUser → AssociateFaces → DynamoDB put; images to S3 SSE-KMS with lifecycle expiry
Ops: CloudWatch dashboard (p50/p95 decision latency, throttles, similarity histogram), X-Ray on Lambda
IaC: SAM/CDK or Amplify Gen 2 (backend.ts attaches liveness IAM policy)
```

- **Latency budget for the ALLOW path** (estimates to measure on the day, not AWS figures):

| Step | Estimate |
|---|---|
| On-device detect and quality gate | about 100-300 ms |
| Upload of a ~150 KB JPEG on venue Wi-Fi | about 100-300 ms |
| API Gateway + warm Lambda | about 20-50 ms |
| SearchUsersByImage | likely a few hundred ms |
| DynamoDB | under 10 ms |
| **Total** | about 0.6-1.3 s, which leaves headroom under 2 s |

  A Lambda cold start (seconds) would break the budget, so pre-warm it or use provisioned concurrency.
- **Fallbacks:**
  - If venue network latency to Mumbai is poor, the on-device embedding can match against a small cached gallery for the demo, with the cloud as the authority.
  - If Rekognition is blocked in the sandbox, fall back to self-hosted InsightFace/ArcFace ONNX on Lambda or EC2.

### Gaps
- No measured Bangalore → ap-south-1 RTT data was retrieved.
- No AWS sample (aws-samples GitHub) for a kiosk liveness architecture was fetched this session. The [Amazon Rekognition Face Liveness samples](https://github.com/aws-samples) repo exists by my prior knowledge but was not verified.

## 6. Hackathon AWS sandbox restrictions (Workshop Studio / Event Engine) and how to cope

### Takeaway
I could not retrieve primary documentation on Workshop Studio event-account restrictions; the pages returned 404 or no content. Based on typical practice, which is unverified, expect region locks, service and instance-type SCP denies (often no GPUs), no quota increases or support cases, short-lived credentials, and account wipe after the event. Verify everything in the first 30 minutes and keep a fallback ready.

### Cited Findings
- Rekognition TPS quota increases require an AWS Support case. The quota-increase questions include use case, APIs, regions and daily volume. A short-lived sandbox cannot realistically raise them, so you have to live with the Mumbai defaults (5 TPS search, 25 TPS compare, 5 TPS and 15 concurrent liveness). — [Rekognition guidelines and quotas](https://docs.aws.amazon.com/rekognition/latest/dg/limits.html); [Rekognition endpoints and quotas](https://docs.aws.amazon.com/general/latest/gr/rekognition.html)
- Indian SMS needs DLT registration with corporate tax IDs, which is impossible within a hackathon. — [India sender ID registration](https://docs.aws.amazon.com/sms-voice/latest/userguide/registrations-sms-senderid-india.md)
- The Rekognition free tier and new-customer credits apply to new standard accounts. Sandbox accounts may differ. — [Rekognition pricing](https://aws.amazon.com/rekognition/pricing/)

### Inferences
**Day-of checklist:**
1. Run `aws sts get-caller-identity` and confirm the region is allowed (`ap-south-1`; fall back to `us-east-1`, which has higher quotas and is also a Liveness region).
2. Smoke-test permissions with `aws rekognition create-collection`, `create-face-liveness-session`, `lambda create-function` and `iam create-role`. IAM role creation is often restricted, so look for pre-provisioned roles.
3. Check whether the Cognito Identity Pool can be created. If not, use `FaceLivenessDetectorCore` with a backend-vended STS credential provider.
4. Check SageMaker and EC2 instance-type availability. Assume no GPU and use CPU ONNX.
5. Credentials usually expire (often within hours), so don't hard-code them. Redeploy via SAM or CDK from a laptop.
6. Keep all code and IaC in Git, because the account is likely wiped after the event.
7. Fall back to email OTP (Cognito or SES; SES sandbox requires verified recipients) or an on-screen TOTP for the "REQUEST VERIFICATION" demo.

### Gaps
- No primary source was found for Workshop Studio or Event Engine participant account restrictions (allowed regions, SCPs, instance types, credential lifetime). The docs URLs tried returned 404 or empty content. Ask the organisers for the allowed services and regions list.
