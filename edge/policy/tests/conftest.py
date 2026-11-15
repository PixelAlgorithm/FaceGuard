"""edge/policy tests: opt-in faked wall clock (POLICY_TEST_WALL_CLOCK, see wallclock.py) + a re-anchored
runtime clock (RT_CLOCK starts at the baseline instant in every test, independent of the run order)."""

import pytest

from edge.policy.tests.builders import RT_CLOCK
from edge.policy.tests.wallclock import fake_wall_clock  # noqa: F401  (autouse fixture)


@pytest.fixture(autouse=True)
def _anchor_runtime_clock() -> None:
    RT_CLOCK.reset()
