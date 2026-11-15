"""V2 build_artifact.sh (edge/auth allowlist + stage import check), CIT-16 (hash-pinned requirements),
CIT-18 (portable mktemp + cleanup in scripts/fetch_models.sh)."""

# ruff: noqa: S603, S607, S105, S106, S108

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from .conftest import INFRA, ROOT

sys.path.insert(0, str(INFRA))
import filter_requirements  # type: ignore[import-not-found]  # noqa: E402

REQ = """annotated-doc==0.0.6 \\
    --hash=sha256:aa \\
    --hash=sha256:bb
    # via fastapi
boto3==1.35.0 \\
    --hash=sha256:cc
uvicorn==0.30.0 \\
    --hash=sha256:dd
"""


def test_filter_drops_whole_blocks_and_keeps_hashes():
    out = filter_requirements.drop_packages(REQ, {"boto3"})
    assert "boto3" not in out and "sha256:cc" not in out
    assert "annotated-doc==0.0.6" in out and "sha256:aa" in out and "sha256:dd" in out


def test_build_script_requires_hashes():
    s = (INFRA / "build_artifact.sh").read_text()
    assert "--no-hashes" not in s and "--require-hashes" in s


def _stage(tmp_path: Path, src_root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(INFRA / "build_artifact.sh"), "--stage-only"], capture_output=True, text=True,
                          timeout=300, env={"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(tmp_path),
                                            "HID_BUILD_DIR": str(tmp_path / "build"),
                                            "HID_SOURCE_ROOT": str(src_root)})


def test_stage_ships_only_allowlisted_edge_auth_and_imports(tmp_path: Path):
    r = _stage(tmp_path, ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    auth = tmp_path / "build" / "stage-ec2" / "app" / "edge" / "auth"
    assert sorted(p.name for p in auth.iterdir()) == ["__init__.py", "rbac.py", "tokens.py"]
    assert "import check ok" in r.stdout


def test_stage_fails_when_rbac_missing(tmp_path: Path):
    src = tmp_path / "src"
    for rel in ("cloud/__init__.py", "cloud/app", "cloud/tools/__init__.py", "cloud/tools/fakeimg.py",
                "edge/__init__.py", "edge/policy", "edge/offline", "edge/auth/__init__.py", "edge/auth/tokens.py",
                "config", "scripts/sign_bundle.py", "cloud/.venv"):
        s, d = ROOT / rel, src / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        if rel == "cloud/.venv":
            d.symlink_to(s)
        elif s.is_dir():
            shutil.copytree(s, d, ignore=shutil.ignore_patterns("__pycache__", "tests"))
        else:
            shutil.copy2(s, d)
    r = _stage(tmp_path, src)
    assert r.returncode != 0
    assert "rbac" in (r.stdout + r.stderr)


# --------------------------------------------------------------------------- fetch_models (CIT-18)
def _fetch(tmp_path: Path, models: Path) -> subprocess.CompletedProcess:
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    curl = fake / "curl"
    curl.write_text('#!/bin/bash\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && { echo bad > "$2"; }; shift; done\n')
    curl.chmod(0o755)
    return subprocess.run(["bash", str(ROOT / "scripts" / "fetch_models.sh")], capture_output=True, text=True,
                          timeout=60, env={"PATH": f"{fake}:/usr/bin:/bin", "FG_MODELS_DIR": str(models)})


def test_fetch_models_stale_literal_part_file_does_not_block(tmp_path: Path):
    models = tmp_path / "models"
    (models / "fixtures").mkdir(parents=True)
    (models / "MiniFASNetV2.onnx.XXXX.part").write_text("stale")  # what the old BSD mktemp left behind
    r = _fetch(tmp_path, models)
    assert "mkstemp" not in r.stderr and "File exists" not in r.stderr
    assert r.stdout.count("FAILED") == 8  # every download verified (stub serves junk) -> all rejected
    leftovers = [p.name for p in models.rglob("*") if p.is_file() and p.name != "MiniFASNetV2.onnx.XXXX.part"]
    assert leftovers == []
    assert r.returncode == 1


def test_fetch_models_never_touches_real_models_dir_in_tests(tmp_path: Path):
    assert "FG_MODELS_DIR" in (ROOT / "scripts" / "fetch_models.sh").read_text()
