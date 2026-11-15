# Edge latency - measured (2026-11-14T09:52:52Z)

Measured by `edge/.venv/bin/python scripts/bench_latency.py --runs 30`, not estimated. The
script ran 30 sequential attempts after 3 warm-up attempts, against a real
`uvicorn edge.app:app` over localhost HTTP.

**Scope.** These are edge-side numbers only. They do not include face lock, the 1000 ms
colour-flash capture window, or browser rendering. The kiosk measures face lock -> decision
rendered itself and reports it via `POST /v1/attempt/{id}/rendered`, which appears as
`/v1/metrics` `latency_ms.client`. That is the number for the slides.

| stage | p50 ms | 95% CI p50 | p95 ms | 95% CI p95 | max ms |
|---|---|---|---|---|---|
| decode + detect + align + quality (5 frames, parallel) | 27.0 | [26, 28] | 31.1 | [29, 44] (upper = max: n too small for a tighter bound) | 44.0 |
| liveness branch: MiniFASNet x2, YOLOX device x5, moire, mask ring, flash | 77.0 | [70, 84] | 94.3 | [90, 127] (upper = max: n too small for a tighter bound) | 127.0 |
| match branch: ArcFace r50 x<=3 + 1:N (+ cloud if configured) | 65.5 | [57, 73] | 89.6 | [81, 91] (upper = max: n too small for a tighter bound) | 91.0 |
| PolicyRuntime.decide | 1.0 | [1, 1] | 2.5 | [2, 5] (upper = max: n too small for a tighter bound) | 5.0 |
| server total: frames received -> decision | 106.5 | [97, 113] | 136.5 | [121, 158] (upper = max: n too small for a tighter bound) | 158.0 |
| X-Latency-Ms (incl. multipart parse) | 107.3 | [99, 114] | 138.9 | [122, 160] (upper = max: n too small for a tighter bound) | 159.6 |
| client RTT POST /frames (localhost HTTP, upload incl.) | 108.2 | [100, 115] | 140.9 | [124, 162] (upper = max: n too small for a tighter bound) | 161.9 |
| client RTT POST /session/start | 1.4 | [1, 2] | 3.3 | [3, 6] (upper = max: n too small for a tighter bound) | 5.7 |

CIs are distribution-free order-statistic bounds (binomial, coverage >= 95 %). Percentiles use
numpy linear interpolation. With n = 30, the p95 upper bound is the sample maximum.

## Setup

- Machine: Apple M4, 10 logical cores, Darwin 27.2.0,
  Python 3.11.18, onnxruntime 1.32.0. Each session uses 2 intra-op
  threads on a thread pool of 8. ArcFace provider: CoreMLExecutionProvider. All other models
  run on the CPU EP.
- Input per attempt: 5 frames of 640x480 JPEG q85 (mean upload
  176 KiB), plus meta with 31 chroma samples
  and 3 flash events.
- Frames are synthetic: the public-domain NASA `astronaut` portrait with a simulated flash
  reflection, from `edge/synth.py`. The face is about 140 px wide, so all quality, PAD, flash and
  match code paths execute. The gallery holds 1 enrolled user (enrolment ok = True). 1:N
  cost is a single [N, 512] matrix product, so gallery size does not move these numbers.
- Policy runtime: **real** (`edge/policy/runtime.py`). Policy version
  2026-11-14.2. Mode OFFLINE, zone MAIN_GATE, schedule bundle
  v42 (FRESH).
  The decision log is encrypted SQLite in a temp dir. Cloud configured: False,
  so the match branch is local-only. The online Rekognition call (timeout 700 ms) is NOT included here.
- Decisions during the run: {'ALLOW': 16, 'STEP_UP': 14, 'DENY': 0}. These decisions are not an accuracy result; the
  synthetic frames exist only to exercise the code paths.
- Startup (spawn -> /v1/health 200, includes model load, warm-up and the PAD self-test):
  2.7 s.
- Machine load (1/5/15-min load average) before: 2.98/3.22/3.23, after:
  3.14/3.25/3.24. Other processes share the CPU (e.g. the kiosk browser with
  MediaPipe and the camera on the same laptop), so compare tables only at similar load.

<details><summary>raw per-run values (ms)</summary>

| # | quality | liveness | match | policy | total | X-Latency-Ms | frames RTT | decision |
|---|---|---|---|---|---|---|---|---|
| 1 | 28 | 85 | 77 | 2 | 115 | 116.1 | 117.2 | ALLOW |
| 2 | 29 | 66 | 58 | 1 | 97 | 98.1 | 99.4 | STEP_UP |
| 3 | 26 | 75 | 51 | 1 | 104 | 104.8 | 105.6 | ALLOW |
| 4 | 24 | 63 | 49 | 1 | 90 | 90.6 | 91.5 | ALLOW |
| 5 | 28 | 67 | 72 | 0 | 101 | 102.3 | 103.1 | STEP_UP |
| 6 | 27 | 68 | 64 | 1 | 97 | 97.5 | 98.3 | ALLOW |
| 7 | 26 | 66 | 56 | 1 | 93 | 93.8 | 94.7 | ALLOW |
| 8 | 24 | 71 | 60 | 1 | 97 | 97.6 | 98.4 | STEP_UP |
| 9 | 25 | 67 | 52 | 1 | 94 | 94.8 | 95.6 | ALLOW |
| 10 | 24 | 84 | 57 | 3 | 113 | 114.1 | 115.4 | ALLOW |
| 11 | 44 | 91 | 91 | 5 | 141 | 144.0 | 146.5 | ALLOW |
| 12 | 27 | 77 | 57 | 1 | 106 | 106.8 | 107.6 | STEP_UP |
| 13 | 27 | 78 | 56 | 1 | 107 | 107.8 | 108.8 | ALLOW |
| 14 | 27 | 87 | 67 | 1 | 117 | 118.5 | 119.8 | ALLOW |
| 15 | 32 | 97 | 88 | 1 | 131 | 132.6 | 134.0 | STEP_UP |
| 16 | 29 | 127 | 71 | 1 | 158 | 159.6 | 161.9 | STEP_UP |
| 17 | 28 | 81 | 71 | 2 | 112 | 112.9 | 114.0 | STEP_UP |
| 18 | 26 | 78 | 84 | 1 | 111 | 112.1 | 113.1 | STEP_UP |
| 19 | 29 | 84 | 73 | 1 | 115 | 116.1 | 117.0 | ALLOW |
| 20 | 29 | 90 | 81 | 1 | 121 | 122.4 | 123.6 | STEP_UP |
| 21 | 29 | 85 | 79 | 2 | 116 | 117.7 | 118.9 | ALLOW |
| 22 | 26 | 82 | 73 | 1 | 111 | 112.0 | 113.2 | ALLOW |
| 23 | 30 | 91 | 91 | 1 | 123 | 124.4 | 125.6 | STEP_UP |
| 24 | 26 | 74 | 75 | 1 | 103 | 104.2 | 105.5 | STEP_UP |
| 25 | 29 | 77 | 69 | 1 | 108 | 109.3 | 110.1 | STEP_UP |
| 26 | 26 | 73 | 64 | 2 | 101 | 102.6 | 103.8 | ALLOW |
| 27 | 21 | 65 | 51 | 1 | 88 | 88.7 | 90.3 | ALLOW |
| 28 | 24 | 69 | 47 | 1 | 95 | 96.1 | 96.9 | STEP_UP |
| 29 | 23 | 68 | 56 | 1 | 93 | 93.8 | 94.6 | STEP_UP |
| 30 | 25 | 70 | 54 | 1 | 97 | 98.8 | 100.3 | ALLOW |

</details>
