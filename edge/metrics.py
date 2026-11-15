"""In-memory decision metrics for GET /v1/metrics (dashboard feed; eval/ owns the official numbers).

Percentiles: numpy linear interpolation over the measured samples. Error-rate upper bounds:
rule of 3 (3/n) when there are 0 errors, else one-sided 95 % Clopper-Pearson.
"""

from __future__ import annotations

import math
import threading
from collections import Counter, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import numpy as np

ATTACK_LABELS = {"print", "screen_photo", "video", "mask_paper", "mask_3d", "injection", "replay", "screen"}
BONA_FIDE = "bona_fide"


@dataclass(frozen=True)
class DecisionRecord:
    ts: datetime
    attempt_id: str
    decision: str
    mode: str
    reason_codes: tuple[str, ...]
    latency: dict[str, float]
    eval_label: str | None


def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """One-sided (1 - alpha) upper bound on a binomial proportion (bisection on the CDF)."""
    if n <= 0:
        return 1.0
    if k >= n:
        return 1.0

    def cdf(p: float) -> float:
        return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k + 1))

    lo, hi = k / n, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        if cdf(mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def error_upper_95(k: int, n: int) -> float | None:
    if n <= 0:
        return None
    return round(3.0 / n if k == 0 else clopper_pearson_upper(k, n), 4)


def _pct(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"p50": None, "p95": None, "n": 0}
    arr = np.asarray(values, dtype=np.float64)
    return {"p50": round(float(np.percentile(arr, 50)), 1), "p95": round(float(np.percentile(arr, 95)), 1),
            "n": len(values)}


class MetricsStore:
    """`frames` records feed latency (the 2 s path); decisions/labels use each attempt's FINAL
    decision (a STEP_UP later resolved to ALLOW counts as ALLOW, i.e. system-level APCER)."""

    def __init__(self, maxlen: int = 5000) -> None:
        self._lock = threading.Lock()
        self._records: deque[DecisionRecord] = deque(maxlen=maxlen)
        self._final: dict[str, DecisionRecord] = {}
        self._client: deque[tuple[datetime, str, float, str | None]] = deque(maxlen=maxlen)

    def record_client(self, attempt_id: str, client_latency_ms: float, eval_label: str | None) -> None:
        """Kiosk-measured face lock -> decision rendered (POST /v1/attempt/{id}/rendered)."""
        with self._lock:
            self._client.append((datetime.now(UTC), attempt_id, float(client_latency_ms), eval_label))

    def record(self, response: dict[str, Any], eval_label: str | None, kind: str = "frames") -> None:
        lat = {k: float(v) for k, v in (response.get("latency_ms") or {}).items() if isinstance(v, int | float)}
        rec = DecisionRecord(
            ts=datetime.now(UTC),
            attempt_id=str(response.get("attempt_id")),
            decision=str(response.get("decision")),
            mode=str(response.get("mode")),
            reason_codes=tuple(response.get("reason_codes") or ()),
            latency=lat if kind == "frames" else {},
            eval_label=eval_label,
        )
        with self._lock:
            if kind == "frames":
                self._records.append(rec)
            prev = self._final.get(rec.attempt_id)
            self._final[rec.attempt_id] = DecisionRecord(
                ts=prev.ts if prev else rec.ts, attempt_id=rec.attempt_id, decision=rec.decision,
                mode=rec.mode, reason_codes=rec.reason_codes, latency={},
                eval_label=rec.eval_label if rec.eval_label else (prev.eval_label if prev else None),
            )
            if len(self._final) > self._records.maxlen:
                for k in list(self._final)[: len(self._final) - self._records.maxlen]:
                    del self._final[k]

    def summary(self, since: datetime | None = None, label: str | None = None,
                sync: dict[str, Any] | None = None) -> dict[str, Any]:
        def keep(r: DecisionRecord) -> bool:
            return (since is None or r.ts >= since) and (label is None or r.eval_label == label)

        with self._lock:
            lat_recs = [r for r in self._records if keep(r)]
            recs = [r for r in self._final.values() if keep(r)]
            client = [ms for ts, _, ms, lab in self._client
                      if (since is None or ts >= since) and (label is None or lab == label)]
        until = datetime.now(UTC)
        by_label: dict[str, Any] = {}
        for lab in sorted({r.eval_label for r in recs if r.eval_label}):
            sub = [r for r in recs if r.eval_label == lab]
            n = len(sub)
            lab_client = {"client": _pct([ms for ts, _, ms, lb in self._client
                                          if lb == lab and (since is None or ts >= since)])}
            if lab == BONA_FIDE:
                rejected = sum(r.decision == "DENY" for r in sub)
                by_label[lab] = {"n": n, "rejected": rejected,
                                 "step_up": sum(r.decision == "STEP_UP" for r in sub),
                                 "bpcer": round(rejected / n, 4), "bpcer_upper_95": error_upper_95(rejected, n),
                                 "latency_ms": lab_client}
            else:
                accepted = sum(r.decision == "ALLOW" for r in sub)
                by_label[lab] = {"n": n, "accepted": accepted, "apcer": round(accepted / n, 4),
                                 "apcer_upper_95": error_upper_95(accepted, n),
                                 "attack_label_known": lab in ATTACK_LABELS, "latency_ms": lab_client}
        stages = sorted({k for r in lat_recs for k in r.latency})
        latency = {st: _pct([r.latency[st] for r in lat_recs if st in r.latency]) for st in stages}
        latency["client"] = _pct(client)
        return {
            "window": {"since": (since or (recs[0].ts if recs else until)).isoformat().replace("+00:00", "Z"),
                       "until": until.isoformat().replace("+00:00", "Z")},
            "attempts": len(recs),
            "decisions": dict(Counter(r.decision for r in recs)),
            "by_mode": dict(Counter(r.mode for r in recs)),
            "reason_codes": dict(Counter(c for r in recs for c in r.reason_codes)),
            "latency_ms": latency,
            "by_label": by_label,
            "sync": sync or {},
            "note": "latency_ms.client = kiosk-measured face lock -> decision rendered; other stages are "
                    "edge-side; face_lock_to_decision_server uses the kiosk clock (same host)",
        }
