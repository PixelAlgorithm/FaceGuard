# Edge metrics snapshot

> Edge dashboard aggregates (`GET /v1/metrics`) + per-attempt decisions (`GET /v1/attempt/{id}`), captured read-only. **Provenance only - not an eval result.** Official numbers with 95% bounds come from `eval/metrics.py` on `attempts.csv`.

- taken 2026-11-14T17:16:21.481Z by `python snapshot_metrics.py --edge http://127.0.0.1:8000`
- edge `http://127.0.0.1:8000` (source: HTTP)
- requests: {'GET /v1/health:200': 1, 'GET /v1/mode:200': 1, 'GET /v1/metrics:200': 1}

Shipped configuration (thresholds.yaml):

- thresholds sha256 `d9e62826253f2137db287561ede0778ce924da9fb6c4cdb1c924a15bc4e97e70`, policy_version `2026-11-14.3`
- colour flash: **ADVISORY** (`liveness.flash.enforce: false`): recorded, no decision effect - replay-species APCER (phone_photo / phone_video / laptop_replay) is measured WITHOUT the flash; 3-3 colours, 700 ms
- moire: enforce `True` (unsure >= 0.4, fail >= 0.7, corroboration True)
- mask M2 RGB ring: enforce `True` (weak >= 0.5, strong >= 0.75)
- depth (`liveness.depth.enabled`): `False`
- random challenge (`challenge.random_rate`): online 0.15, offline 0.3; deformation ['SMILE', 'OPEN_MOUTH'] + secondary ['BLINK', 'TURN_LEFT', 'TURN_RIGHT']; RANDOM_CHALLENGE first decisions count as step-up (never in BPCER)
- rate limit: enabled `True`, 5 in 180 s -> lockout 5 s
- Rekognition (`match.rekognition.enabled`): `True`; local allow_min_cosine 0.5

Edge vs thresholds.yaml (`GET /v1/mode` policy_bars): consistent

Edge `/v1/metrics`: attempts 4, decisions {'DENY': 4}, by_mode {'ONLINE': 4}

| edge latency key | p50 ms | p95 ms | n |
|---|---|---|---|
| face_lock_to_decision_server | 1062.5 | 2172.3 | 4 |
| liveness | 120.0 | 125.1 | 4 |
| match | 125.5 | 141.5 | 4 |
| policy | 1.5 | 3.7 | 4 |
| quality | 44.0 | 64.5 | 4 |
| schedule | 0.0 | 0.0 | 4 |
| total | 171.5 | 209.1 | 4 |
| client | 1094.0 | 1124.6 | 3 |

Attempts requested 0, found 0, not found / not decided 0.

Privacy findings (values redacted):

- mode.template_cache: forbidden key
- health.detail.template_cache: forbidden key
