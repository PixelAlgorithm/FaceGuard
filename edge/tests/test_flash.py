"""Colour-flash correlation: synthetic reflection model, lag, tamper and weak-signal cases."""

from __future__ import annotations

import numpy as np

from edge.ml.flash import Event, Step, chroma, flash_signal, hex_to_rgb

FRAME_MS = 1000.0 / 30.0
SEQ = [Step("#FF4D4D", 0, 333), Step("#4DFF6A", 333, 333), Step("#4D6BFF", 666, 334)]
START = 1_000_000.0
SKIN = np.array([180.0, 130.0, 110.0])  # RGB


def respond(color: str | None, gain: float = 0.12) -> np.ndarray:
    if color is None:
        return SKIN.copy()
    c = hex_to_rgb(color) / 255.0
    return np.clip(SKIN * (1.0 + gain * (c - c.mean())), 0, 255)


def colour_at(seq, t_rel):
    for s in seq:
        if s.offset_ms <= t_rel < s.offset_ms + s.duration_ms:
            return s.color
    return None


def series(seq, *, lag_ms=50.0, gain=0.12, step_ms=FRAME_MS, respond_to=None, noise=0.3, seed=0):
    rng = np.random.default_rng(seed)
    out = []
    for k in range(int(1000 / step_ms) + 1):
        t = START + k * step_ms
        col = colour_at(respond_to or seq, t - START - lag_ms) if gain > 0 else None
        v = respond(col, gain) + rng.normal(0, noise, 3)
        out.append((t, *v))
    return out


def frames(seq, *, lag_ms=50.0, gain=0.12, respond_to=None, n=5):
    out = []
    for i in range(n):
        t = START + 1000.0 * (i + 0.6) / n
        col = colour_at(respond_to or seq, t - START - lag_ms) if gain > 0 else None
        out.append((t, *respond(col, gain)))
    return out


def events(seq, jitter=0.0):
    return [Event(i, s.color, START + s.offset_ms + jitter) for i, s in enumerate(seq)]


def run(seq=SEQ, ev=None, fr=None, cl=None, min_amp=4.0, lag_max=3.0):
    return flash_signal(seq, events(seq) if ev is None else ev, START, fr if fr is not None else frames(seq),
                        cl if cl is not None else series(seq), FRAME_MS, min_amp, lag_max)


def test_live_response_correlates_with_small_lag():
    a = run()
    s = a.signal
    assert s.r is not None and s.r >= 0.9
    assert 0.0 <= s.lag_frames <= 3.0
    assert s.lag_std_frames is not None and s.lag_std_frames <= 1.0
    assert s.amplitude is not None and s.amplitude >= 4.0
    assert s.order_ok is True


def test_no_response_is_weak_not_high_r():
    a = run(fr=frames(SEQ, gain=0.0), cl=series(SEQ, gain=0.0))
    assert a.signal.amplitude is not None and a.signal.amplitude < 4.0
    assert "FLASH_WEAK_SIGNAL" in a.reason_candidates


def test_response_to_a_different_sequence_has_low_r_or_wrong_order():
    replayed = [Step("#4D6BFF", 0, 333), Step("#FF4D4D", 333, 333), Step("#4DFF6A", 666, 334)]
    a = run(fr=frames(SEQ, respond_to=replayed), cl=series(SEQ, respond_to=replayed))
    # r is now edge-frames-only (5 samples, coarser: ~0.43 here); the replay is still a hard flash FAIL
    # because the colour ORDER is wrong (DECISION_POLICY 3.3: wrong order => SPOOF_FLASH_MISMATCH).
    assert a.signal.r is not None and (a.signal.r < 0.3 or a.signal.order_ok is False)
    assert a.signal.order_ok is False


def test_replay_lag_is_reported_outside_window():
    a = run(fr=frames(SEQ, lag_ms=200.0), cl=series(SEQ, lag_ms=200.0))
    assert a.signal.lag_frames is not None and a.signal.lag_frames > 3.0


def test_tampered_paint_log_sets_order_false():
    bad = [Event(0, "#FF4D4D", START), Event(1, "#4D6BFF", START + 333), Event(2, "#4DFF6A", START + 666)]
    a = run(ev=bad)
    assert a.signal.order_ok is False
    assert "FLASH_EVENTS_MISMATCH" in a.reason_candidates


def test_forged_client_series_cannot_raise_r():
    """Frames show a non-responding screen; the browser claims a perfect response."""
    a = run(fr=frames(SEQ, gain=0.0), cl=series(SEQ))
    assert a.r_client is not None and a.r_client > 0.9
    assert a.signal.r is not None and a.signal.r <= a.r_frames + 1e-9
    assert a.signal.r < 0.7


def test_frames_must_cover_two_segments():
    fr = [(START + 50.0 + 20 * i, *respond("#FF4D4D")) for i in range(4)]  # all inside segment 0
    a = run(fr=fr)
    assert a.signal.r is None
    assert "FLASH_FRAMES_INSUFFICIENT" in a.reason_candidates


def test_missing_events_give_unknown_order():
    a = run(ev=[])
    assert a.signal.order_ok is None
    assert a.signal.r is not None  # falls back to the issued offsets


def test_noise_only_is_never_a_strong_pass():
    rng = np.random.default_rng(3)
    fr = [(START + 200.0 * i + 120, *(SKIN + rng.normal(0, 2.0, 3))) for i in range(5)]
    cl = [(START + FRAME_MS * k, *(SKIN + rng.normal(0, 2.0, 3))) for k in range(31)]
    a = run(fr=fr, cl=cl)
    assert a.signal.amplitude is None or a.signal.amplitude < 4.0 or (a.signal.r or 0) < 0.7


def test_chroma_cancels_gain():
    rgb = np.array([[100.0, 80.0, 60.0]])
    assert np.allclose(chroma(rgb), chroma(rgb * 1.7))


def test_every_palette_order_live_passes_and_rotated_replay_fails():
    """Exhaustive over all ordered 3-colour draws from the kiosk palette (regression for order_ok)."""
    import itertools

    from edge.session import FLASH_PALETTE

    for cols in itertools.permutations(FLASH_PALETTE, 3):
        seq = [Step(cols[0], 0, 333), Step(cols[1], 333, 333), Step(cols[2], 666, 334)]
        live = run(seq=seq, fr=frames(seq, lag_ms=66.0), cl=series(seq, lag_ms=66.0, noise=0.0)).signal
        assert live.order_ok is True and live.r >= 0.9 and live.amplitude >= 4.0, cols
        rotated = [Step(seq[(i + 1) % 3].color, seq[i].offset_ms, seq[i].duration_ms) for i in range(3)]
        rep = run(seq=seq, fr=frames(seq, lag_ms=66.0, respond_to=rotated),
                  cl=series(seq, lag_ms=66.0, respond_to=rotated, noise=0.0)).signal
        assert rep.order_ok is False or (rep.r or 0) < 0.3, cols
