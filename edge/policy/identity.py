"""Stage 4 identity decision (DECISION_POLICY §3.5). Pure.

ONLINE: Rekognition is authoritative; the local matcher can only tighten (cross-check + identity
consistency). OFFLINE: local ArcFace only, with the offline (stricter) bars. A stale/unknown template
cache makes the local matcher unusable (offline -> NOT_ENROLLED; online -> cannot cross-check).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from statistics import fmean
from typing import Any

from edge.policy.codes import dedupe
from edge.policy.quality import finite
from edge.policy.signals import CloudMatch, FrameSignals

PASS, UNSURE, FAIL = "PASS", "UNSURE", "FAIL"


@dataclass(frozen=True)
class LocalSummary:
    user: str
    top1: float
    top2: float | None  # None = no *different* user in the gallery
    consistent: bool


@dataclass(frozen=True)
class IdentityResult:
    status: str
    codes: tuple[str, ...]
    user_id: str | None
    scores: dict[str, Any] = field(default_factory=dict)


def local_summary(frames: Sequence[FrameSignals], cache_age_h: float | None, T: Any) -> LocalSummary | None:
    if not finite(cache_age_h) or cache_age_h < 0 or cache_age_h > T.cache.template_cache_max_age_hours:
        return None  # unknown or stale template cache is unusable
    matched = [f for f in frames if f.match_top1_user and finite(f.match_top1)]
    if not matched:
        return None
    cand = matched[0].match_top1_user
    same = [f for f in matched if f.match_top1_user == cand]
    top2s = [f.match_top2 for f in same if finite(f.match_top2)]
    # verify M01: ANY embedded frame whose top-1 is a different enrolled user at or above the deny bar breaks
    # identity consistency (a victim photo + attacker live face burst), not only a mismatch on the last frame
    deny = float(T.match.local.deny_below_cosine)
    other = any(f.match_top1_user != cand and f.match_top1 >= deny for f in matched)
    return LocalSummary(
        user=str(cand),
        top1=fmean(f.match_top1 for f in same),
        top2=fmean(top2s) if top2s else None,
        consistent=matched[-1].match_top1_user == cand and not other,
    )


def _local_status(s: LocalSummary, Lc: Any) -> tuple[str, list[str]]:
    if s.top1 < Lc.deny_below_cosine:
        return FAIL, ["NOT_ENROLLED"]
    if s.top1 < Lc.allow_min_cosine:
        return UNSURE, ["MATCH_LOW"]
    if s.top2 is not None and (s.top1 - s.top2) < Lc.min_margin_top1_top2:
        return UNSURE, ["MATCH_AMBIGUOUS"]
    return PASS, []


def identity_match(frames: Sequence[FrameSignals], cloud: CloudMatch | None, T: Any, mode: str,
                   cache_age_h: float | None) -> IdentityResult:
    Lc = T.match.local
    loc = local_summary(frames, cache_age_h, T)
    scores: dict[str, Any] = {
        "match_local": loc.top1 if loc else None,
        "match_margin": (loc.top1 - loc.top2) if loc and loc.top2 is not None else None,
        "rekognition": None,
        "rekognition_runner_up": None,
    }
    require_same = bool(Lc.require_same_identity_first_last_frame)

    if mode == "OFFLINE":
        if loc is None:
            return IdentityResult(FAIL, ("NOT_ENROLLED",), None, scores)
        status, codes = _local_status(loc, Lc)
        if status != FAIL and require_same and not loc.consistent:
            status, codes = UNSURE, codes + ["MATCH_AMBIGUOUS"]
        return IdentityResult(status, tuple(dedupe(codes)), loc.user, scores)

    if cloud is None or not cloud.ok:
        raise ValueError("online identity requires a successful cloud match (caller must flip to OFFLINE)")
    R = T.match.rekognition
    sim, ru = cloud.top1_similarity, cloud.runner_up_similarity
    scores["rekognition"] = sim if finite(sim) else None
    scores["rekognition_runner_up"] = ru if finite(ru) else None
    if not cloud.top1_user or not finite(sim) or sim < R.deny_below_similarity:
        return IdentityResult(FAIL, ("NOT_ENROLLED",), cloud.top1_user or (loc.user if loc else None), scores)
    user = cloud.top1_user
    codes: list[str] = []
    if sim < R.allow_min_similarity:
        codes.append("MATCH_LOW")
    elif finite(ru) and ru >= R.runner_up_max_similarity:
        codes.append("MATCH_AMBIGUOUS")
    if loc is None:
        codes.append("MATCH_AMBIGUOUS")  # cannot cross-check / verify consistency -> never auto-ALLOW
    else:
        if (T.match.cross_check_local_conflict and loc.user != user
                and loc.top1 >= T.identity.cross_check_conflict_min_cosine):
            codes.append("MATCH_AMBIGUOUS")
        if require_same and not loc.consistent:
            codes.append("MATCH_AMBIGUOUS")
    codes = dedupe(codes)
    return IdentityResult(UNSURE if codes else PASS, tuple(codes), user, scores)
