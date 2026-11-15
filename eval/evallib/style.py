"""Charts for metrics.py / summary.py, following the dataviz skill.

Palette = the skill's validated reference instance (references/palette.md), validated for this use with
scripts/validate_palette.py: slots 1-3 PASS light + dark (light aqua has a contrast WARN -> charts carry
direct labels and SUMMARY.md has a table view for every chart). Rules applied: single series -> slot 1, no
legend box (title names it); >= 2 series -> legend; colour follows the entity (fixed species order);
thin marks, hairline solid grid, recessive axes; text never wears a series colour; targets/thresholds are
thin dashed muted lines with a direct label; small multiples instead of > 4 converging lines.
Every chart is rendered twice: <name>.png (light) and <name>_dark.png (dark, own steps).
"""

from __future__ import annotations

import math
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import norm

THEMES: dict[str, dict[str, str]] = {
    "light": {
        "surface": "#fcfcfb", "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781",
        "grid": "#e1e0d9", "axis": "#c3c2b7", "s1": "#2a78d6", "s2": "#eb6834", "s3": "#1baf7a",
        "deemph": "#898781",
    },
    "dark": {
        "surface": "#1a1a19", "ink": "#f0efec", "ink2": "#c3c2b7", "muted": "#898781",
        "grid": "#2c2c2a", "axis": "#383835", "s1": "#3987e5", "s2": "#d95926", "s3": "#199e70",
        "deemph": "#898781",
    },
}
FONT = ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"]


def _setup(theme: str) -> dict[str, str]:
    t = THEMES[theme]
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": FONT,
        "font.size": 10,
        "axes.facecolor": t["surface"],
        "figure.facecolor": t["surface"],
        "savefig.facecolor": t["surface"],
        "axes.edgecolor": t["axis"],
        "axes.labelcolor": t["ink2"],
        "axes.titlecolor": t["ink"],
        "axes.titlesize": 11,
        "axes.titleweight": "bold",
        "axes.titlelocation": "left",
        "axes.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.color": t["grid"],
        "grid.linewidth": 0.8,
        "grid.linestyle": "-",
        "xtick.color": t["muted"],
        "ytick.color": t["muted"],
        "xtick.labelcolor": t["ink2"],
        "ytick.labelcolor": t["ink2"],
        "legend.frameon": False,
        "legend.labelcolor": t["ink2"],
        "text.color": t["ink"],
        "lines.solid_capstyle": "round",
        "lines.solid_joinstyle": "round",
    })
    return t


def _save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)


def _both(draw, path: Path) -> list[str]:
    """Render light + dark variants; return written paths."""
    out = []
    for theme, suffix in (("light", ""), ("dark", "_dark")):
        t = _setup(theme)
        p = path.with_name(path.stem + suffix + path.suffix)
        fig = draw(t)
        _save(fig, p)
        out.append(str(p))
    return out


def _subtitle(ax, text: str, t: dict) -> None:
    ax.text(0.0, 1.02, text, transform=ax.transAxes, fontsize=8.5, color=t["ink2"], va="bottom", ha="left")


# --------------------------------------------------------------------- DET (normal-deviate axes)

DET_TICKS = [0.001, 0.002, 0.006, 0.01, 0.02, 0.05, 0.1, 0.2, 0.4, 0.6]


def _probit(x: np.ndarray, floor: float) -> np.ndarray:
    return norm.ppf(np.clip(np.asarray(x, dtype=float), floor, 1 - floor))


def plot_det_matcher(
    path: Path,
    test: tuple[np.ndarray, np.ndarray] | None,
    dev: tuple[np.ndarray, np.ndarray] | None,
    points: list[tuple[str, float, float]],
    title: str,
    n_text: str,
) -> list[str]:
    """DET of FMR (x) vs FNMR (y). test = slot 1 (reported), dev = de-emphasis gray (tuned on)."""
    from .det import det_points

    def draw(t):
        fig, ax = plt.subplots(figsize=(5.6, 5.0))
        floors = []
        series = []
        if dev is not None and len(dev[0]) and len(dev[1]):
            series.append(("dev split (tuned on)", dev, t["deemph"], 1.5))
        if test is not None and len(test[0]) and len(test[1]):
            series.append(("test split (reported)", test, t["s1"], 2.0))
        for name, (g, i), col, lw in series:
            _, fmr, fnmr = det_points(g, i)
            fl = 0.5 / max(len(i), len(g))
            floors.append(fl)
            ax.plot(_probit(fmr, fl), _probit(fnmr, fl), color=col, lw=lw, label=name, zorder=3)
        fl = min(floors) if floors else 1e-3
        lo = norm.ppf(max(fl, 5e-4))
        for x, lab in ((0.002, "HID FAR 0.2%"),):
            ax.axvline(norm.ppf(x), color=t["muted"], lw=0.9, ls=(0, (4, 3)), zorder=2)
            ax.text(norm.ppf(x), norm.ppf(0.55), f" {lab}", color=t["ink2"], fontsize=8, rotation=90,
                    va="top", ha="right")
        ax.axhline(norm.ppf(0.006), color=t["muted"], lw=0.9, ls=(0, (4, 3)), zorder=2)
        ax.text(norm.ppf(0.55), norm.ppf(0.006), "HID FRR 0.6% ", color=t["ink2"], fontsize=8, va="bottom",
                ha="right")
        for lab, fx, fy in points:
            if any(map(math.isnan, (fx, fy))):
                continue
            px, py = _probit(np.array([fx]), fl)[0], _probit(np.array([fy]), fl)[0]
            ax.scatter([px], [py], s=48, color=t["ink"], edgecolor=t["surface"], linewidth=2, zorder=5)
            ax.annotate(lab, (px, py), xytext=(6, 6), textcoords="offset points", fontsize=8, color=t["ink"])
        yt = [v for v in DET_TICKS if norm.ppf(v) >= lo - 1e-9]
        xt = [v for v in yt if v != 0.006]  # 0.6% collides with 1% on the x axis
        ax.set_xticks(norm.ppf(xt), [f"{v:.1%}" if v < 0.01 else f"{v:.0%}" for v in xt], fontsize=8)
        ax.set_yticks(norm.ppf(yt), [f"{v:.1%}" if v < 0.01 else f"{v:.0%}" for v in yt], fontsize=8)
        ax.set_xlim(lo - 0.15, norm.ppf(0.6))
        ax.set_ylim(lo - 0.15, norm.ppf(0.6))
        ax.set_xlabel("False match rate (FMR)")
        ax.set_ylabel("False non-match rate (FNMR)")
        ax.set_title(title, pad=22)
        _subtitle(ax, n_text + "  ·  points on the axis floor = 0 errors observed", t)
        if len(series) >= 2:
            ax.legend(loc="upper right", fontsize=8)
        return fig

    return _both(draw, path)


def plot_det_pad(path: Path, per_species: dict[str, tuple[np.ndarray, np.ndarray]], title: str) -> list[str]:
    """Small multiples, one panel per species: APCER (x) vs BPCER (y) on PAD liveness score."""
    from .det import det_points

    names = [s for s, (b, a) in per_species.items() if len(b) and len(a)]
    if not names:
        return []
    cols = min(3, len(names))
    rows = math.ceil(len(names) / cols)

    def draw(t):
        fig, axes = plt.subplots(rows, cols, figsize=(3.3 * cols, 3.1 * rows), squeeze=False)
        for idx, ax in enumerate(axes.flat):
            if idx >= len(names):
                ax.set_visible(False)
                continue
            sp = names[idx]
            b, a = per_species[sp]
            _, apcer, bpcer = det_points(b, a)
            fl = 0.5 / max(len(a), len(b))
            ax.plot(_probit(apcer, fl), _probit(bpcer, fl), color=t["s1"], lw=2, zorder=3)
            lo = norm.ppf(max(fl, 5e-4))
            ticks = [v for v in (0.01, 0.05, 0.2, 0.5) if norm.ppf(v) >= lo]
            ax.set_xticks(norm.ppf(ticks), [f"{v:.0%}" for v in ticks], fontsize=7)
            ax.set_yticks(norm.ppf(ticks), [f"{v:.0%}" for v in ticks], fontsize=7)
            ax.set_xlim(lo - 0.15, norm.ppf(0.6))
            ax.set_ylim(lo - 0.15, norm.ppf(0.6))
            ax.set_title(f"{sp}  (attacks {len(a)}, bona fide {len(b)})", fontsize=9, pad=4)
            if idx % cols == 0:
                ax.set_ylabel("BPCER", fontsize=8)
            if idx // cols == rows - 1:
                ax.set_xlabel("APCER", fontsize=8)
        fig.suptitle(title, x=0.01, ha="left", fontsize=11, fontweight="bold", color=t["ink"])
        fig.text(0.01, 0.955 - 0.01 * rows, "one panel per attack species; bona fide = same set in every panel; "
                 "points on the axis floor = 0 errors observed", fontsize=8, color=t["ink2"], ha="left")
        fig.tight_layout(rect=(0, 0, 1, 0.93 - 0.01 * rows))
        return fig

    return _both(draw, path)


# --------------------------------------------------------------------- rates with upper-bound whiskers

def plot_rate_bars(
    path: Path,
    rows: list[tuple[str, dict]],
    title: str,
    subtitle: str,
    xlabel: str,
    target: tuple[float, str] | None = None,
) -> list[str]:
    """Horizontal bars = point estimate, whisker = one-sided 95 % UB, direct label k/N. One series -> slot 1."""
    if not rows:
        return []

    def draw(t):
        h = 0.55 * len(rows) + 1.3
        fig, ax = plt.subplots(figsize=(6.4, h))
        ys = np.arange(len(rows))[::-1]
        xmax = max([r[1]["ub95"] for r in rows if not math.isnan(r[1]["ub95"])] + [0.05])
        for y, (name, rec) in zip(ys, rows, strict=True):
            n = rec["n"]
            if n == 0:
                ax.text(0, y, "  no data", va="center", fontsize=8, color=t["muted"])
                continue
            ax.barh(y, rec["rate"], height=0.42, color=t["s1"], zorder=3)
            ax.plot([rec["rate"], rec["ub95"]], [y, y], color=t["ink2"], lw=1.2, zorder=4)
            ax.plot([rec["ub95"]] * 2, [y - 0.13, y + 0.13], color=t["ink2"], lw=1.2, zorder=4)
            ax.text(rec["ub95"] + xmax * 0.015, y, f"{rec['k']}/{n}  (UB {100 * rec['ub95']:.1f}%)",
                    va="center", fontsize=8, color=t["ink"])
        if target:
            ax.axvline(target[0], color=t["muted"], lw=0.9, ls=(0, (4, 3)), zorder=2)
            ax.text(target[0], len(rows) - 0.45, f" {target[1]}", fontsize=8, color=t["ink2"], va="bottom")
        ax.set_yticks(ys, [r[0] for r in rows], fontsize=9)
        ax.set_xlim(0, xmax * 1.45)
        ax.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0, decimals=0))
        ax.grid(axis="y", visible=False)
        ax.axvline(0, color=t["axis"], lw=0.8, zorder=2)
        ax.set_xlabel(xlabel)
        ax.set_title(title, pad=22)
        _subtitle(ax, subtitle, t)
        return fig

    return _both(draw, path)


def plot_latency_hist(
    path: Path,
    per_mode: dict[str, np.ndarray],
    sla_ms: float,
    title: str,
    source_text: str,
) -> list[str]:
    """One histogram panel per mode (small multiples), p50/p95 markers (staggered labels), 2 s target line."""
    modes = [m for m, v in per_mode.items() if len(v)]
    if not modes:
        return []

    def draw(t):
        fig, axes = plt.subplots(len(modes), 1, figsize=(6.6, 2.4 * len(modes) + 0.9), squeeze=False)
        allv = np.concatenate([per_mode[m] for m in modes])
        hi = max(float(allv.max()), sla_ms) * 1.1
        bins = np.linspace(0, hi, 31)
        for i, (ax, m) in enumerate(zip(axes.flat, modes, strict=True)):
            v = per_mode[m]
            ax.hist(v, bins=bins, color=t["s1"], rwidth=0.88, zorder=3)
            p50, p95 = float(np.quantile(v, 0.5)), float(np.quantile(v, 0.95))
            ymax = ax.get_ylim()[1] * 1.25
            ax.set_ylim(0, ymax)
            for x, lab, yf in ((p50, "p50", 0.97), (p95, "p95", 0.80)):
                ax.axvline(x, color=t["ink"], lw=1.0, zorder=4)
                ax.text(x, ymax * yf, f" {lab} {x:.0f} ms", fontsize=8, color=t["ink"], va="top")
            ax.axvline(sla_ms, color=t["muted"], lw=0.9, ls=(0, (4, 3)), zorder=2)
            ax.text(sla_ms, ymax * 0.60, f" target {sla_ms / 1000:.0f} s", fontsize=8, color=t["ink2"])
            ax.text(0.0, 0.97, f"{m}  (n = {len(v)})", transform=ax.transAxes, fontsize=9, fontweight="bold",
                    color=t["ink"], va="top")
            ax.set_xlim(0, hi)
            ax.grid(axis="x", visible=False)
            ax.set_ylabel("attempts", fontsize=8)
            if i == 0:
                ax.set_title(title, pad=24)
                _subtitle(ax, source_text, t)
        axes.flat[-1].set_xlabel("milliseconds")
        fig.tight_layout()
        return fig

    return _both(draw, path)


def plot_stage_ranges(path: Path, rows: list[tuple[str, float, float, int]], title: str, subtitle: str) -> list[str]:
    """Per-stage p50 bar with whisker to p95 (stages run partly in parallel -> not stacked)."""
    rows = [r for r in rows if r[3] > 0 and not math.isnan(r[1])]
    if not rows:
        return []

    def draw(t):
        fig, ax = plt.subplots(figsize=(6.4, 0.55 * len(rows) + 1.3))
        ys = np.arange(len(rows))[::-1]
        xmax = max(r[2] for r in rows)
        for y, (name, p50, p95, n) in zip(ys, rows, strict=True):
            ax.barh(y, p50, height=0.42, color=t["s1"], zorder=3)
            ax.plot([p50, p95], [y, y], color=t["ink2"], lw=1.2, zorder=4)
            ax.plot([p95] * 2, [y - 0.13, y + 0.13], color=t["ink2"], lw=1.2, zorder=4)
            ax.text(p95 + xmax * 0.015, y, f"p50 {p50:.0f} · p95 {p95:.0f} ms (n {n})", va="center", fontsize=8,
                    color=t["ink"])
        ax.set_yticks(ys, [r[0] for r in rows], fontsize=9)
        ax.set_xlim(0, xmax * 1.55)
        ax.grid(axis="y", visible=False)
        ax.axvline(0, color=t["axis"], lw=0.8)
        ax.set_xlabel("milliseconds")
        ax.set_title(title, pad=22)
        _subtitle(ax, subtitle, t)
        return fig

    return _both(draw, path)
