"""DET points / EER / operating points. Convention: higher score = more similar (matcher) or more live (PAD).

Accept rule everywhere: score >= threshold  (same as the edge: top1 >= allow_min_cosine).
  matcher: FMR(t) = P(impostor >= t),  FNMR(t) = P(genuine < t)
  PAD:     APCER(t) = P(attack >= t),  BPCER(t) = P(bona fide < t)
"""

from __future__ import annotations

import numpy as np


def det_points(genuine: np.ndarray, impostor: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Exact DET over every distinct score (no quantile thinning). Returns thresholds, FMR, FNMR."""
    g = np.sort(np.asarray(genuine, dtype=float))
    i = np.sort(np.asarray(impostor, dtype=float))
    if g.size == 0 or i.size == 0:
        return np.array([]), np.array([]), np.array([])
    ts = np.unique(np.concatenate([g, i, [np.inf]]))
    fmr = 1.0 - np.searchsorted(i, ts, side="left") / i.size  # share of impostor >= t
    fnmr = np.searchsorted(g, ts, side="left") / g.size  # share of genuine < t
    return ts, fmr, fnmr


def eer(genuine: np.ndarray, impostor: np.ndarray) -> dict:
    ts, fmr, fnmr = det_points(genuine, impostor)
    if ts.size == 0:
        return {"eer": float("nan"), "threshold": float("nan")}
    j = int(np.argmin(np.abs(fmr - fnmr)))
    return {"eer": float((fmr[j] + fnmr[j]) / 2.0), "threshold": float(ts[j]), "fmr": float(fmr[j]),
            "fnmr": float(fnmr[j])}


def counts_at(genuine: np.ndarray, impostor: np.ndarray, t: float) -> tuple[int, int, int, int]:
    """(k_false_match, n_impostor, k_false_non_match, n_genuine) at threshold t (accept: score >= t)."""
    g = np.asarray(genuine, dtype=float)
    i = np.asarray(impostor, dtype=float)
    return int((i >= t).sum()), int(i.size), int((g < t).sum()), int(g.size)


def calibrate_threshold(impostor: np.ndarray, percentile: float) -> dict:
    """allow_min_cosine suggestion = given percentile of impostor scores (numpy 'linear').

    Resolution note: the p-th percentile is only distinguishable from the max when
    N * (1 - p/100) >= 1 (e.g. 99.8th pct needs N >= 500 impostor scores).
    """
    i = np.asarray(impostor, dtype=float)
    n = int(i.size)
    if n == 0:
        return {"n_impostor": 0, "threshold": float("nan"), "resolution_ok": False}
    t = float(np.percentile(i, percentile))
    need = int(np.ceil(1.0 / (1.0 - percentile / 100.0)))
    k_dev = int((i >= t).sum())
    return {
        "n_impostor": n,
        "percentile": percentile,
        "threshold": t,
        "impostor_max": float(i.max()),
        "dev_false_matches_at_threshold": k_dev,
        "resolution_ok": n >= need,
        "n_needed_for_resolution": need,
    }
