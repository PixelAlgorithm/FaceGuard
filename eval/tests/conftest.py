from __future__ import annotations

import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(EVAL))


@pytest.fixture
def fixtures() -> Path:
    return FIX


@pytest.fixture
def dummy_args(tmp_path: Path) -> list[str]:
    """CLI args for an end-to-end metrics.py run on the DUMMY fixtures, output in a tmp dir."""
    return ["--attempts", str(FIX / "attempts_DUMMY.csv"), "--comparisons", str(FIX / "comparisons_DUMMY.csv"),
            "--scenarios", str(FIX / "scenarios_DUMMY.csv"), "--exclusions", str(FIX / "exclusions_DUMMY.csv"),
            "--out-dir", str(tmp_path / "out"), "--boot", "300"]
