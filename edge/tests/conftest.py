"""Shared fixtures. Model-backed fixtures are session-scoped (load + warm once, ~1.5 s).

HERMETIC (verifier rule): the tests never read the project `.env` and never reach the real cloud.
At import time this conftest
  * puts DUMMY values for every secret / setting into the process env (a fresh Fernet key, dummy admin /
    depth tokens, CLOUD_API_URL="" so no heartbeat or sync ever leaves the machine, a scratch EDGE_DATA_DIR),
  * turns both `.env` readers (edge.config.load_dotenv for Settings, edge.policy.runtime.read_env for
    PolicyRuntime.from_env) into no-ops for the real project `.env`,
  * makes every PolicyRuntime built in these tests use TEST_CLOCK: a clock that starts at a fixed
    in-window time of day (2026-11-14 11:00 IST) and advances with the monotonic clock, so results never
    depend on when the suite runs (after 21:00 IST some tests used to read SCHEDULE_OUTSIDE_WINDOW).
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import edge.config as edge_config
from edge.config import PROJECT_ROOT, Settings, Thresholds
from edge.ml.registry import MODEL_FILES

MODELS_DIR = PROJECT_ROOT / "models"
HAVE_MODELS = all((MODELS_DIR / m.filename).is_file() for m in MODEL_FILES.values())
requires_models = pytest.mark.skipif(not HAVE_MODELS, reason="run: bash scripts/fetch_models.sh")

REAL_DOTENV = (PROJECT_ROOT / ".env").resolve()
TEST_KIOSK = "KIOSK_MAIN_01"
TEST_BUNDLE_KEY = "test-bundle-hmac-key"
HERMETIC_ENV: dict[str, str] = {
    "KIOSK_ID": TEST_KIOSK,
    "EDGE_DATA_KEY": Fernet.generate_key().decode(),
    "SCHEDULE_BUNDLE_HMAC_KEY": TEST_BUNDLE_KEY,
    "CARD_ID_PEPPER": "test-card-pepper",
    "KIOSK_HMAC_KEY": "test-kiosk-hmac-key",
    "CLOUD_API_URL": "",  # never the real cloud: no heartbeats, no syncing synthetic decisions
    "CLOUD_API_KEY": "test-cloud-api-key",
    "ADMIN_TOKEN": "test-admin-token",
    "DEPTH_DEVICE_TOKEN": "test-depth-token",
    "FORCE_OFFLINE": "0",
    "DEMO_MODE": "1",
    "EDGE_LAN_PORT": "0",  # the LAN listener has its own test on a free port
    "EDGE_DATA_DIR": tempfile.mkdtemp(prefix="edge_test_data_"),
}
os.environ.update(HERMETIC_ENV)
os.environ.pop("BUNDLE_PATH", None)

# Fixed time of day for every PolicyRuntime in these tests (schedule windows, bundle freshness).
TEST_NOW = datetime(2026, 11, 14, 5, 30, tzinfo=UTC)  # 11:00 Asia/Kolkata, inside the example bundle validity
_MONO0 = time.monotonic()


def TEST_CLOCK() -> datetime:
    return TEST_NOW + timedelta(seconds=time.monotonic() - _MONO0)


# ---- never read the real .env ------------------------------------------------------------------------
_orig_load_dotenv = edge_config.load_dotenv


def _hermetic_load_dotenv(path: Path, *, override: bool = False) -> None:
    if Path(path).resolve() == REAL_DOTENV:
        return
    _orig_load_dotenv(path, override=override)


edge_config.load_dotenv = _hermetic_load_dotenv


def _install_runtime_guards() -> None:
    from edge.policy import runtime as rt_mod

    def _hermetic_read_env(project_root: Path) -> dict[str, str]:
        return {k: os.environ[k] for k in rt_mod.ENV_KEYS if k in os.environ}

    rt_mod.read_env = _hermetic_read_env
    orig = rt_mod.PolicyRuntime.from_env.__func__
    if getattr(orig, "_hermetic", False):
        return

    def _from_env(cls, project_root, *, env=None, transport=None, clock=None):
        return orig(cls, project_root, env=env, transport=transport, clock=clock or TEST_CLOCK)

    _from_env._hermetic = True  # type: ignore[attr-defined]
    rt_mod.PolicyRuntime.from_env = classmethod(_from_env)


_install_runtime_guards()


# ---- fixtures ----------------------------------------------------------------------------------------
@pytest.fixture(scope="session")
def thresholds() -> Thresholds:
    return Thresholds.load(PROJECT_ROOT / "config" / "thresholds.yaml")


@pytest.fixture(scope="session")
def test_env() -> dict[str, str]:
    """The hermetic env (dummy secrets, scratch data dir). Kept as a fixture for existing tests."""
    return {"data_dir": HERMETIC_ENV["EDGE_DATA_DIR"]}


@pytest.fixture(scope="session")
def settings(test_env) -> Settings:
    s = Settings.from_env()
    assert s.admin_token == HERMETIC_ENV["ADMIN_TOKEN"] and not s.cloud_api_url  # hermetic, never the .env
    return s


@pytest.fixture(scope="session")
def engine(settings, thresholds):
    if not HAVE_MODELS:
        pytest.skip("models missing")
    from edge.perception import PerceptionEngine

    eng = PerceptionEngine(settings, thresholds)
    eng.load()
    return eng


@pytest.fixture(scope="session")
def client(engine, settings):
    from fastapi.testclient import TestClient

    from edge.app import build_context, create_app

    app = create_app(lambda: build_context(settings, engine))
    with TestClient(app) as c:
        yield c


class SecretHeaders(dict):
    """Header mapping whose repr never shows the secret (pytest prints fixture values on failure)."""

    def __repr__(self) -> str:
        return "{" + ", ".join(f"{k!r}: '***'" for k in self) + "}"


@pytest.fixture(scope="session")
def admin_headers(settings) -> SecretHeaders:
    return SecretHeaders({"X-Admin-Token": settings.admin_token})


def project_path(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)


@pytest.fixture
def example_bundle(client, monkeypatch):
    """The signed config/schedule.example.json as the session runtime's verified bundle, for this test only
    (enrolment needs the user in the bundle). Restored afterwards (the scratch data dir has no bundle file)."""
    import json

    from edge.offline.bundle import sign_bundle

    example = json.loads(project_path("config", "schedule.example.json").read_text(encoding="utf-8"))
    signed = sign_bundle(example, TEST_BUNDLE_KEY.encode())
    monkeypatch.setattr(client.app.state.ctx.runtime.bundles, "_lvb", signed)
    return signed


# scratch edge app + contract-shaped fake cloud (edge/tests/contract_cloud.py), used by the v1.4 contract tests
from edge.tests.contract_cloud import make_env  # noqa: F401
