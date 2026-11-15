"""Error-rate statistics with exact (Clopper-Pearson) bounds.

Conventions (pad-evaluation skill section 3):
  * zero errors in N trials -> one-sided 95 % upper bound = 1 - 0.05**(1/N)  (~ 3/N, "rule of 3")
  * k > 0 errors           -> one-sided Clopper-Pearson upper bound beta.ppf(0.95, k+1, N-k)
  * never the normal approximation for small k
  * report as "k/N = p (95% UB = x%)"

Formatting is conservative: error rates and upper bounds are rounded UP at the displayed precision,
accuracies / lower bounds are rounded DOWN, so a displayed number never flatters the system.
"""

from __future__ import annotations

import math
from collections.abc import Sequence

import numpy as np
from scipy.stats import beta

CONF = 0.95
NAN = float("nan")


def _check(k: int, n: int) -> None:
    if n < 0 or k < 0 or k > n:
        raise ValueError(f"invalid counts k={k} n={n}")


def cp_upper(k: int, n: int, conf: float = CONF) -> float:
    """One-sided Clopper-Pearson upper bound. k=0 -> 1-(1-conf)**(1/n) (~3/n at 95 %)."""
    _check(k, n)
    if n == 0:
        return NAN
    if k >= n:
        return 1.0
    return float(beta.ppf(conf, k + 1, n - k))


def cp_lower(k: int, n: int, conf: float = CONF) -> float:
    """One-sided Clopper-Pearson lower bound."""
    _check(k, n)
    if n == 0:
        return NAN
    if k == 0:
        return 0.0
    return float(beta.ppf(1.0 - conf, k, n - k + 1))


def cp_two_sided(k: int, n: int, conf: float = CONF) -> tuple[float, float]:
    """Two-sided Clopper-Pearson interval (each tail (1-conf)/2)."""
    _check(k, n)
    if n == 0:
        return (NAN, NAN)
    a = 1.0 - conf
    lo = 0.0 if k == 0 else float(beta.ppf(a / 2, k, n - k + 1))
    hi = 1.0 if k == n else float(beta.ppf(1 - a / 2, k + 1, n - k))
    return (lo, hi)


def rule_of_three(n: int) -> float:
    """Approximate 95 % upper bound for 0 errors in n trials (3/n)."""
    return 3.0 / n if n > 0 else NAN


def zero_error_upper_exact(n: int, conf: float = CONF) -> float:
    """Exact one-sided upper bound for 0/n: 1-(1-conf)**(1/n). Equals cp_upper(0, n)."""
    return 1.0 - (1.0 - conf) ** (1.0 / n) if n > 0 else NAN


def trials_needed(p_target: float, k_errors: int = 0, conf: float = CONF) -> int:
    """Smallest N such that the one-sided CP upper bound with k_errors errors is <= p_target."""
    if not 0 < p_target < 1:
        raise ValueError("p_target must be in (0, 1)")
    if k_errors == 0:
        n = math.ceil(math.log(1.0 - conf) / math.log(1.0 - p_target))
        while n > 1 and cp_upper(0, n - 1, conf) <= p_target:  # guard float edge
            n -= 1
        while cp_upper(0, n, conf) > p_target:
            n += 1
        return n
    lo, hi = k_errors + 1, k_errors + 1
    while cp_upper(k_errors, hi, conf) > p_target:
        hi *= 2
        if hi > 10**9:
            raise ValueError("target not reachable")
    while lo < hi:  # cp_upper is decreasing in n for fixed k
        mid = (lo + hi) // 2
        if cp_upper(k_errors, mid, conf) <= p_target:
            hi = mid
        else:
            lo = mid + 1
    return lo


# --------------------------------------------------------------------- conservative formatting

def _round_dir(x: float, decimals: int, up: bool) -> float:
    f = 10**decimals
    v = x * f
    v = math.ceil(v - 1e-9) if up else math.floor(v + 1e-9)
    return v / f


def pct(x: float | None, decimals: int = 2, up: bool = True) -> str:
    """Percent string rounded conservatively (up for error rates / UBs, down for accuracies)."""
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "n/a"
    return f"{_round_dir(100.0 * x, decimals, up):.{decimals}f}%"


def rate(k: int, n: int, conf: float = CONF, higher_is_better: bool = False) -> dict:
    """Standard rate record used everywhere in metrics.json.

    higher_is_better=False (error rates): headline bound = one-sided upper bound `ub95`.
    higher_is_better=True (e.g. fraction within SLA): headline bound = one-sided lower bound `lb95`.
    """
    k, n = int(k), int(n)
    _check(k, n)
    r = k / n if n else NAN
    lo2, hi2 = cp_two_sided(k, n, conf) if n else (NAN, NAN)
    rec: dict = {
        "k": k,
        "n": n,
        "rate": r,
        "ub95": cp_upper(k, n, conf) if n else NAN,
        "lb95": cp_lower(k, n, conf) if n else NAN,
        "ci95_two_sided": [lo2, hi2],
        "zero_errors": (k == 0) if not higher_is_better else None,
    }
    if n == 0:
        rec["text"] = "0/0 (no data)"
    elif higher_is_better:
        rec["text"] = f"{k}/{n} = {pct(r, up=False)} (95% LB = {pct(rec['lb95'], up=False)})"
    else:
        rec["text"] = f"{k}/{n} = {pct(r)} (95% UB = {pct(rec['ub95'])})"
        if k == 0:
            rec["rule_of_3"] = rule_of_three(n)
            rec["rule_of_3_text"] = (
                f"0/{n} -> < 3/{n} = {pct(rule_of_three(n))} (rule of 3); exact 95% UB = {pct(rec['ub95'])}"
            )
    return rec


# --------------------------------------------------------------------- quantiles + bootstrap

def quantile(x: Sequence[float] | np.ndarray, q: float) -> float:
    """q in [0, 1]; numpy 'linear' interpolation (documented in PROTOCOL.md)."""
    a = np.asarray(x, dtype=float)
    if a.size == 0:
        return NAN
    return float(np.quantile(a, q))


def bootstrap_quantile_ci(
    x: Sequence[float] | np.ndarray,
    q: float,
    n_boot: int = 2000,
    conf: float = CONF,
    seed: int = 20261114,
) -> tuple[float, float]:
    """Percentile-bootstrap CI for the q-quantile (resample with replacement, fixed seed)."""
    a = np.asarray(x, dtype=float)
    if a.size == 0:
        return (NAN, NAN)
    if a.size == 1:
        return (float(a[0]), float(a[0]))
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, a.size, size=(n_boot, a.size))
    qs = np.quantile(a[idx], q, axis=1)
    lo, hi = np.quantile(qs, [(1 - conf) / 2, 1 - (1 - conf) / 2])
    return (float(lo), float(hi))


def latency_summary(
    x: Sequence[float] | np.ndarray,
    sla_ms: float | None = None,
    n_boot: int = 2000,
    seed: int = 20261114,
    low_n: int = 20,
) -> dict:
    """p50/p95/max with bootstrap 95 % CIs, plus fraction <= SLA (CP bounds)."""
    a = np.asarray([v for v in x if v is not None and not math.isnan(float(v))], dtype=float)
    out: dict = {"n": int(a.size)}
    if a.size == 0:
        out.update({"p50": NAN, "p95": NAN, "max": NAN, "p50_ci95": [NAN, NAN], "p95_ci95": [NAN, NAN]})
        return out
    out["p50"] = quantile(a, 0.50)
    out["p95"] = quantile(a, 0.95)
    out["max"] = float(a.max())
    out["mean"] = float(a.mean())
    out["p50_ci95"] = list(bootstrap_quantile_ci(a, 0.50, n_boot, seed=seed))
    out["p95_ci95"] = list(bootstrap_quantile_ci(a, 0.95, n_boot, seed=seed))
    out["low_n"] = bool(a.size < low_n)
    if sla_ms is not None:
        k = int((a <= sla_ms).sum())
        out["sla_ms"] = sla_ms
        out["within_sla"] = rate(k, int(a.size), higher_is_better=True)
    return out
