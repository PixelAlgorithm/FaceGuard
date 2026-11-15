from __future__ import annotations

import copy

import numpy as np
import pytest

from depth import synth
from depth.checks import load_thresholds


@pytest.fixture(scope="session")
def cfg() -> dict:
    """The real config/thresholds.yaml: tests must not hard-code thresholds."""
    return load_thresholds()


@pytest.fixture
def cfg_copy(cfg: dict) -> dict:
    return copy.deepcopy(cfg)


@pytest.fixture(scope="session")
def cam() -> synth.SynthCamera:
    return synth.SynthCamera(320, 240)


@pytest.fixture
def rng() -> np.random.Generator:
    return np.random.default_rng(1234)


def noisy(frame: synth.SynthFrame, rng: np.random.Generator, **kw) -> synth.SynthFrame:
    frame.depth_m = synth.add_sensor_noise(frame.depth_m, rng, **kw)
    return frame
