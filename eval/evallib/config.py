"""Shipped-configuration switches recorded with every run (RUN_INFO.md, run manifests, snapshots).

Read-only view of config/thresholds.yaml: nothing here changes a threshold. The live edge reports the same switches
in GET /v1/mode `policy_bars`; `compare_with_edge` flags any difference (e.g. thresholds.yaml edited but the edge
not restarted), so a number is never attributed to a configuration that was not actually running.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import io as eio


def _get(d: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = d
    for k in dotted.split("."):
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def shipped_switches(th: dict, path: Path | None = None) -> dict:
    """The decision-relevant switches of the configuration under test (pad-evaluation skill: record with the hash)."""
    flash_enforce = _get(th, "liveness.flash.enforce")
    return {
        "thresholds_path": str(path) if path else None,
        "thresholds_sha256": eio.sha256_file(path) if path else None,
        "policy_version": th.get("policy_version"),
        "flash": {
            "enabled": _get(th, "liveness.flash.enabled"),
            "enforce": flash_enforce,
            "state": "ENFORCED" if flash_enforce else "ADVISORY",
            "duration_ms": _get(th, "liveness.flash.duration_ms"),
            "colours": [_get(th, "liveness.flash.colours_min"), _get(th, "liveness.flash.colours_max")],
        },
        "moire": {
            "enforce": _get(th, "liveness.moire.enforce"),
            "unsure_score": _get(th, "liveness.moire.unsure_score"),
            "fail_score": _get(th, "liveness.moire.fail_score"),
            "require_corroboration": _get(th, "liveness.moire.require_corroboration"),
        },
        "mask_m2_rgb": {
            "enforce": _get(th, "liveness.mask.m2_rgb_enforce"),
            "weak": _get(th, "liveness.mask.m2_ring_score_weak"),
            "strong": _get(th, "liveness.mask.m2_ring_score_strong"),
        },
        "pad": {"pass_min": _get(th, "liveness.pad.pass_min"), "fail_max": _get(th, "liveness.pad.fail_max"),
                "min_pass_frames": _get(th, "liveness.pad.min_pass_frames")},
        "device_detector": {"unsure_conf": _get(th, "liveness.device_detector.unsure_conf"),
                            "fail_conf": _get(th, "liveness.device_detector.fail_conf")},
        "depth_enabled": _get(th, "liveness.depth.enabled"),
        "random_challenge": {
            "rate_online": _get(th, "challenge.random_rate"),
            "rate_offline": _get(th, "offline.overrides.challenge.random_rate", _get(th, "challenge.random_rate")),
            "deformation_actions": _get(th, "challenge.deformation_actions"),
            "secondary_actions": _get(th, "challenge.secondary_actions"),
        },
        "rate_limit": {
            "enabled": _get(th, "rate_limit.enabled"),
            "max_failures": _get(th, "rate_limit.max_failures"),
            "window_s": _get(th, "rate_limit.window_s"),
            "lockout_s": _get(th, "rate_limit.lockout_s"),
        },
        "rekognition_enabled": _get(th, "match.rekognition.enabled"),
        "match_local_allow_min_cosine": _get(th, "match.local.allow_min_cosine"),
    }


# GET /v1/mode policy_bars key -> path in shipped_switches()
EDGE_BAR_MAP = {
    "flash_enforce": "flash.enforce",
    "moire_enforce": "moire.enforce",
    "m2_rgb_enforce": "mask_m2_rgb.enforce",
    "rekognition": "rekognition_enabled",
    "random_rate": "random_challenge.rate_online",
    "moire_unsure": "moire.unsure_score",
    "device_unsure": "device_detector.unsure_conf",
    "pad_pass": "pad.pass_min",
    "match_allow": "match_local_allow_min_cosine",
}


def compare_with_edge(sw: dict, mode: dict | None) -> list[str]:
    """Differences between thresholds.yaml and what the running edge reports (empty list = consistent).

    In OFFLINE mode the edge reports the offline overrides, so only the switches (not bars) are compared then."""
    if not isinstance(mode, dict) or not isinstance(mode.get("policy_bars"), dict):
        return ["edge /v1/mode policy_bars unavailable - live switches not cross-checked"]
    bars = mode["policy_bars"]
    offline = str(mode.get("mode") or "").upper() == "OFFLINE"
    out = []
    if mode.get("policy_version") and mode["policy_version"] != sw.get("policy_version"):
        out.append(f"policy_version: edge {mode['policy_version']} != thresholds.yaml {sw.get('policy_version')}")
    for key, path in EDGE_BAR_MAP.items():
        if key not in bars:
            continue
        if offline and key not in ("flash_enforce", "moire_enforce", "m2_rgb_enforce", "rekognition"):
            continue
        want = _get(sw, path)
        got = bars[key]
        same = (abs(float(got) - float(want)) < 1e-9 if isinstance(got, (int, float)) and not isinstance(got, bool)
                and isinstance(want, (int, float)) and not isinstance(want, bool) else got == want)
        if not same:
            out.append(f"{key}: edge {got!r} != thresholds.yaml {want!r}")
    return out


def switch_lines(sw: dict) -> list[str]:
    """Markdown bullet lines for RUN_INFO.md / SNAPSHOT.md (wording follows the pad-evaluation honesty rules)."""
    f, m, k, rc, rl = sw["flash"], sw["moire"], sw["mask_m2_rgb"], sw["random_challenge"], sw["rate_limit"]
    flash_txt = ("ENFORCED" if f["enforce"] else
                 "**ADVISORY** (`liveness.flash.enforce: false`): recorded, no decision effect - replay-species "
                 "APCER (phone_photo / phone_video / laptop_replay) is measured WITHOUT the flash")
    return [
        f"- thresholds sha256 `{sw['thresholds_sha256']}`, policy_version `{sw['policy_version']}`",
        f"- colour flash: {flash_txt}; {f['colours'][0]}-{f['colours'][1]} colours, {f['duration_ms']} ms",
        (f"- moire: enforce `{m['enforce']}` (unsure >= {m['unsure_score']}, fail >= {m['fail_score']}, "
         f"corroboration {m['require_corroboration']})"),
        f"- mask M2 RGB ring: enforce `{k['enforce']}` (weak >= {k['weak']}, strong >= {k['strong']})",
        f"- depth (`liveness.depth.enabled`): `{sw['depth_enabled']}`",
        (f"- random challenge (`challenge.random_rate`): online {rc['rate_online']}, offline {rc['rate_offline']}; "
         f"deformation {rc['deformation_actions']} + secondary {rc['secondary_actions']}; RANDOM_CHALLENGE "
         "first decisions count as step-up (never in BPCER)"),
        (f"- rate limit: enabled `{rl['enabled']}`, {rl['max_failures']} in {rl['window_s']} s -> lockout "
         f"{rl['lockout_s']} s"),
        (f"- Rekognition (`match.rekognition.enabled`): `{sw['rekognition_enabled']}`; local allow_min_cosine "
         f"{sw['match_local_allow_min_cosine']}"),
    ]
