"""policy-fixes: verify M01 -- a burst whose embedded frames name two different users is never a clean match."""

from __future__ import annotations

import pytest

from edge.policy.tests.builders import OB, B


@pytest.mark.parametrize("scn", [B, OB])
def test_M01_mixed_identity_burst_is_ambiguous_not_allow(scn):
    local = [("u_3c4d", 0.72, 0.41), ("u_1a2b", 0.70, 0.40), ("u_1a2b", 0.70, 0.40), ("u_1a2b", 0.70, 0.40),
             ("u_3c4d", 0.72, 0.41)]
    d = scn().set(local=local).evaluate()
    assert d.decision != "ALLOW" and "MATCH_AMBIGUOUS" in d.reason_codes, d.reason_codes


def test_M01_unmatched_middle_frames_still_allow():
    local = [("u_3c4d", 0.72, 0.41), (None, None, None), (None, None, None), (None, None, None),
             ("u_3c4d", 0.72, 0.41)]
    assert OB().set(local=local).evaluate().decision == "ALLOW"


def test_M01_low_scoring_other_user_below_the_deny_bar_does_not_break_consistency():
    local = [("u_3c4d", 0.72, 0.41)] * 2 + [("u_1a2b", 0.20, 0.10)] + [("u_3c4d", 0.72, 0.41)] * 2
    assert OB().set(local=local).evaluate().decision == "ALLOW"
