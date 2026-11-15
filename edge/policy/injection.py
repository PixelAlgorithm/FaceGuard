"""Stage 2 injection check (DECISION_POLICY §3.2). Pure. Returns PASS | UNSURE | FAIL."""

from __future__ import annotations

import itertools
from collections.abc import Sequence
from typing import Any

from edge.policy.signals import CameraMeta, FrameSignals


def _intervals_ok(ts: Sequence[int], lo: float, hi: float) -> bool:
    return all(lo <= (b - a) <= hi and b > a for a, b in itertools.pairwise(ts))


def injection_check(camera: CameraMeta, frames: Sequence[FrameSignals], T: Any) -> str:
    """`frames` = ALL submitted frames (timing must not be judged on the gaps left by dropped frames)."""
    inj = T.injection
    label = (camera.camera_label or "").strip().lower()
    if camera.virtual_camera_suspected:
        return "FAIL"
    if any(str(p).lower() in label for p in inj.virtual_camera_label_patterns):
        return "FAIL"
    lo, hi = float(inj.min_frame_interval_ms), float(inj.max_frame_interval_ms)
    cam_ts = list(camera.frame_timestamps_ms)
    frame_ts = [f.ts_ms for f in sorted(frames, key=lambda f: f.index)]
    if any(b <= a for a, b in itertools.pairwise(frame_ts)):
        return "FAIL"  # frames out of capture order / duplicated timestamps
    timing = cam_ts if len(cam_ts) >= 2 else frame_ts
    if len(timing) >= 2 and not _intervals_ok(timing, lo, hi):
        return "FAIL"
    if len(timing) < 2:
        return "UNSURE"  # frame timing cannot be verified
    known = any(str(p).lower() in label for p in inj.known_good_label_patterns)
    if not label or not known:
        return "UNSURE" if inj.unknown_label_is_unsure else "PASS"
    return "PASS"
