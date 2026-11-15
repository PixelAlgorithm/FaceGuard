"""policy-fixes: every PolicyRuntime attribute the edge app looks up by name (getattr / _safe_call / ctx.runtime.X)
must exist -- a missing one silently degrades (e.g. an offline DPDP erasure reported "failed" instead of queued)."""

from __future__ import annotations

import re
from pathlib import Path

from edge.policy.runtime import PolicyRuntime

EDGE = Path(__file__).resolve().parents[2]
CALLERS = ("app.py", "attempts.py", "enroll.py", "access.py", "metrics.py", "events.py", "policy_facade.py")
_PATTERNS = (
    re.compile(r"""(?:_safe_call|getattr)\((?:ctx\.runtime|rt|runtime)\s*,\s*["']([a-z_][a-z0-9_]*)["']"""),
    re.compile(r"""ctx\.runtime\.([a-z_][a-z0-9_]*)\("""),
)
# Optional fallbacks the callers try only when the primary name is missing, plus instance attributes.
ALTERNATES = {"enqueue_cloud_erasure", "pull_revocations_now"}
INSTANCE_ATTRS = {"monitor", "bundles", "overlay", "credentials", "sync", "kiosk_id", "_lock", "_erased", "log",
                  "cfg", "fallback_state", "verifier", "limiter", "sessions", "enrolments", "demo_mode"}


def _names() -> set[str]:
    out: set[str] = set()
    for name in CALLERS:
        path = EDGE / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for pat in _PATTERNS:
            out |= set(pat.findall(text))
    return out


def test_every_runtime_name_the_edge_app_uses_exists():
    names = _names()
    assert "queue_cloud_erasure" in names  # the scan itself works
    missing = sorted(n for n in names - ALTERNATES - INSTANCE_ATTRS if not hasattr(PolicyRuntime, n))
    assert missing == [], f"PolicyRuntime lacks {missing}"


def test_queue_cloud_erasure_is_defined_on_the_class_itself():
    # tests/test_round6.py monkeypatch.delattr(PolicyRuntime, "queue_cloud_erasure") needs it in the class dict
    assert "queue_cloud_erasure" in PolicyRuntime.__dict__
