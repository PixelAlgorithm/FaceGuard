"""Metric math: Clopper-Pearson bounds, rule of 3, trials needed, bootstrap CIs, conservative formatting."""

from __future__ import annotations

import math

import numpy as np
import pytest
from scipy.stats import binom

from evallib import stats as st


@pytest.mark.parametrize("n", [1, 5, 30, 58, 150, 1497])
def test_zero_error_upper_bound_is_exact_rule_of_three(n):
    ub = st.cp_upper(0, n)
    assert ub == pytest.approx(1 - 0.05 ** (1 / n), rel=1e-9)
    assert ub == pytest.approx(st.zero_error_upper_exact(n), rel=1e-12)
    # rule of 3 is a conservative approximation: 3/n >= exact bound, relative excess ~1.5/n
    if n >= 2:
        assert st.rule_of_three(n) >= ub
        assert st.rule_of_three(n) / ub - 1 < 2.0 / n + 0.01


def test_skill_example_0_of_58_print_attacks():
    # pad-evaluation skill section 9.2: "0/58 print attacks accepted -> APCER < 5.2% (95% upper bound)"
    r = st.rate(0, 58)
    assert r["ub95"] < 0.052 and r["ub95"] > 0.050
    assert "0/58" in r["text"] and "95% UB" in r["text"]
    assert r["rule_of_3"] == pytest.approx(3 / 58)
    assert "rule of 3" in r["rule_of_3_text"]


@pytest.mark.parametrize("k,n", [(1, 10), (3, 40), (2, 300), (5, 60), (10, 10)])
def test_cp_upper_defines_binomial_tail(k, n):
    ub = st.cp_upper(k, n)
    if k == n:
        assert ub == 1.0
        return
    # P(X <= k | p = UB) == 0.05 exactly (definition of the one-sided CP bound)
    assert binom.cdf(k, n, ub) == pytest.approx(0.05, abs=1e-9)


@pytest.mark.parametrize("k,n", [(0, 20), (1, 20), (7, 40), (20, 20)])
def test_two_sided_interval_brackets_point(k, n):
    lo, hi = st.cp_two_sided(k, n)
    p = k / n
    assert lo <= p <= hi
    if k == 0:
        assert lo == 0.0
    if k == n:
        assert hi == 1.0
    # two-sided 95 % upper > one-sided 95 % upper
    if k < n:
        assert hi > st.cp_upper(k, n)


def test_lower_bound_zero_when_no_successes():
    assert st.cp_lower(0, 50) == 0.0
    lb = st.cp_lower(50, 50)
    assert lb == pytest.approx(0.05 ** (1 / 50), rel=1e-9)


@pytest.mark.parametrize("p,k,expected", [
    # the skill's table (section 3.2, one-sided 95 %) - must be reproduced exactly
    (0.002, 0, 1497), (0.002, 1, 2371), (0.002, 2, 3146),
    (0.006, 0, 498), (0.006, 1, 789), (0.006, 2, 1048),
    (0.05, 0, 59), (0.05, 1, 93), (0.05, 2, 124),
    (0.02, 0, 149), (0.02, 1, 236), (0.02, 2, 313),
    (0.15, 0, 19), (0.15, 1, 30), (0.15, 2, 40),
])
def test_trials_needed_matches_skill_table(p, k, expected):
    n = st.trials_needed(p, k)
    assert n == expected
    assert st.cp_upper(k, n) <= p < st.cp_upper(k, n - 1)


def test_invalid_counts_raise():
    with pytest.raises(ValueError):
        st.cp_upper(5, 3)
    with pytest.raises(ValueError):
        st.rate(-1, 3)


def test_empty_rate_is_nan_not_zero():
    r = st.rate(0, 0)
    assert math.isnan(r["rate"]) and math.isnan(r["ub95"])
    assert r["text"] == "0/0 (no data)"


def test_conservative_rounding_never_flatters():
    # error rate 1/3 -> 33.34% (up), accuracy 2/3 -> 66.66% (down); exact values stay exact
    assert st.pct(1 / 3) == "33.34%"
    assert st.pct(2 / 3, up=False) == "66.66%"
    assert st.pct(0.05) == "5.00%"
    assert st.pct(0.99375, decimals=1, up=False) == "99.3%"  # never rounded up to 99.4%
    assert st.pct(float("nan")) == "n/a"


def test_bootstrap_ci_contains_quantile_and_is_deterministic():
    rng = np.random.default_rng(0)
    x = rng.normal(1400, 150, 200)
    lo, hi = st.bootstrap_quantile_ci(x, 0.95, n_boot=1000, seed=7)
    q = st.quantile(x, 0.95)
    assert lo <= q <= hi
    assert (lo, hi) == st.bootstrap_quantile_ci(x, 0.95, n_boot=1000, seed=7)
    assert hi - lo < 200


def test_latency_summary_fields_and_sla_fraction():
    x = [1000, 1200, 1500, 1900, 2100]
    s = st.latency_summary(x, sla_ms=2000, n_boot=200)
    assert s["n"] == 5 and s["max"] == 2100
    assert s["p50"] == 1500
    assert s["within_sla"]["k"] == 4 and s["within_sla"]["n"] == 5
    assert s["low_n"] is True
    assert "95% LB" in s["within_sla"]["text"]


def test_latency_summary_ignores_missing():
    s = st.latency_summary([None, float("nan"), 900.0], sla_ms=2000, n_boot=50)
    assert s["n"] == 1 and s["p95"] == 900.0
