"""Thresholds loader (config/thresholds.yaml).

Base values = ONLINE. OFFLINE = deep_merge(base, offline.overrides). Offline overrides may only
tighten pass bars (P6) -- a loosening override is a ConfigError, not a silent fail-open.
Missing keys raise ConfigError so a bad config surfaces as SYSTEM_ERROR (P1), never as a default.
"""

from __future__ import annotations

import copy
import math
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import yaml

from edge.policy.signals import DEFORMATION_ACTIONS, SECONDARY_ACTIONS

MODES = ("ONLINE", "OFFLINE")
RISK_LEVELS = {"low": 0, "medium": 1, "high": 2}
REQUIRED_SECTIONS = (
    "policy_version", "timezone", "latency_budget_ms", "quality", "injection", "liveness", "match",
    "challenge", "stepup", "schedule", "rate_limit", "connectivity", "cache", "offline_store", "sync",
    "fallback", "offline", "identity",
)
# (dotted path, direction): offline value must be >= online ("min") for these pass bars.
_TIGHTEN_ONLY = (
    ("liveness.pad.pass_min", "min"),
    ("liveness.pad.min_pass_frames", "min"),
    ("liveness.flash.pass_min_r", "min"),
    ("match.local.allow_min_cosine", "min"),
    ("match.local.min_margin_top1_top2", "min"),
    ("challenge.random_rate", "min"),
    ("liveness.pad.fail_max", "same"),
    ("liveness.flash.fail_max_r", "same"),
    ("match.local.deny_below_cosine", "same"),
)
# Optional enforce switches (a missing key = enforce; edge/policy/liveness.py `enforced`). Must be booleans;
# offline may never switch one off while it is on online (P6: offline only tightens).
ENFORCE_SWITCHES = ("liveness.flash.enforce", "liveness.moire.enforce", "liveness.mask.m2_rgb_enforce")
# Cloud match budgets (ms) read by edge/attempts.py + edge/cloud_client.py: a missing / non-numeric / non-positive
# value would silently mean "no deadline" or "always time out", so it is a ConfigError at load (P1).
POSITIVE_BUDGETS = ("latency_budget_ms.rekognition_timeout", "latency_budget_ms.rekognition_probe_deadline")


class ConfigError(ValueError):
    """Invalid, unparsable or incomplete thresholds configuration."""


def deep_merge(base: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(dict(base))
    for k, v in patch.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), Mapping):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


class Cfg(Mapping[str, Any]):
    """Read-only nested view with attribute access (`T.liveness.pad.pass_min`)."""

    __slots__ = ("_data", "_path")

    def __init__(self, data: Mapping[str, Any], path: str = "") -> None:
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "_path", path)

    def _wrap(self, key: str, value: Any) -> Any:
        if isinstance(value, Mapping):
            return Cfg(value, f"{self._path}{key}.")
        return value

    def __getattr__(self, name: str) -> Any:
        if name.startswith("__"):
            raise AttributeError(name)
        try:
            return self._wrap(name, self._data[name])
        except KeyError:
            raise ConfigError(f"missing config key: {self._path}{name}") from None

    def __getitem__(self, key: str) -> Any:
        try:
            return self._wrap(key, self._data[key])
        except KeyError:
            raise ConfigError(f"missing config key: {self._path}{key}") from None

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __contains__(self, key: object) -> bool:  # Mapping's default would raise ConfigError for a missing key
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Cfg is read-only")

    def get(self, key: str, default: Any = None) -> Any:
        return self._wrap(key, self._data[key]) if key in self._data else default

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self._data))

    def __repr__(self) -> str:
        return f"Cfg({self._path or '<root>'})"


def _get(d: Mapping[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        cur = cur[part]
    return cur


class Thresholds(Cfg):
    """Resolved thresholds for one mode. Immutable; use for_mode()/with_overrides() for variants."""

    __slots__ = ("_raw", "_variants", "mode")

    def __init__(self, raw: Mapping[str, Any], mode: str = "ONLINE", _validated: bool = False) -> None:
        if mode not in MODES:
            raise ConfigError(f"unknown mode: {mode!r}")
        if not _validated:
            _validate(raw)
        resolved = raw if mode == "ONLINE" else deep_merge(raw, raw["offline"].get("overrides") or {})
        super().__init__(resolved)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "_variants", {mode: self})

    @classmethod
    def load(cls, path: str | Path) -> Thresholds:
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot load thresholds {path}: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise ConfigError("thresholds root must be a mapping")
        return cls(raw, "ONLINE")

    @property
    def policy_version(self) -> str:
        return str(self["policy_version"])

    def for_mode(self, mode: str) -> Thresholds:
        if mode not in MODES:
            raise ConfigError(f"unknown mode: {mode!r}")
        variant = self._variants.get(mode)
        if variant is None:
            variant = Thresholds(self._raw, mode, _validated=True)
            variant._variants.update(self._variants)
            self._variants[mode] = variant
        return variant

    def with_overrides(self, patch: Mapping[str, Any]) -> Thresholds:
        """Deep-merge `patch` into the base (ONLINE) values; offline overrides re-applied on top."""
        return Thresholds(deep_merge(self._raw, patch), self.mode)

    def raw(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self._raw))


def _switch(d: Mapping[str, Any], dotted: str) -> bool:
    parent, _, key = dotted.rpartition(".")
    try:
        section = _get(d, parent)
    except (KeyError, TypeError) as exc:
        raise ConfigError(f"missing config key: {parent}") from exc
    if not isinstance(section, Mapping):
        raise ConfigError(f"{parent} must be a mapping")
    value = section.get(key, True)
    if not isinstance(value, bool):  # "false" (string) or 0 would silently mean something else
        raise ConfigError(f"{dotted} must be true or false, got {value!r}")
    return value


def _check_challenge_actions(cfg: Mapping[str, Any]) -> None:
    """The challenge always needs a mouth/cheek deformation (never blink-only, eye-cut masks blink)."""
    ch = cfg.get("challenge")
    if not isinstance(ch, Mapping):
        raise ConfigError("challenge must be a mapping")
    deform, second = ch.get("deformation_actions"), ch.get("secondary_actions")
    if not (isinstance(deform, list) and deform and all(isinstance(a, str) for a in deform)
            and set(deform) <= DEFORMATION_ACTIONS):
        raise ConfigError(f"challenge.deformation_actions must be a non-empty subset of {sorted(DEFORMATION_ACTIONS)}"
                          f" (mouth/cheek movement, never blink-only), got {deform!r}")
    if not (isinstance(second, list) and all(isinstance(a, str) for a in second) and set(second) <= SECONDARY_ACTIONS
            and (second or int(ch.get("steps", 2)) < 2)):
        raise ConfigError(f"challenge.secondary_actions must be a subset of {sorted(SECONDARY_ACTIONS)} (non-empty"
                          f" when challenge.steps >= 2), got {second!r}")


def _validate(raw: Mapping[str, Any]) -> None:
    missing = [s for s in REQUIRED_SECTIONS if s not in raw]
    if missing:
        raise ConfigError(f"thresholds missing sections: {missing}")
    off = raw["offline"]
    if not isinstance(off, Mapping):
        raise ConfigError("offline must be a mapping")
    if off.get("auto_allow_max_risk") not in RISK_LEVELS:
        raise ConfigError(f"offline.auto_allow_max_risk must be one of {list(RISK_LEVELS)}")
    overrides = off.get("overrides") or {}
    merged = deep_merge(raw, overrides)
    for dotted, direction in _TIGHTEN_ONLY:
        try:
            on, offv = _get(raw, dotted), _get(merged, dotted)
        except (KeyError, TypeError) as exc:
            raise ConfigError(f"missing config key: {dotted}") from exc
        if not all(isinstance(v, int | float) and math.isfinite(v) for v in (on, offv)):
            raise ConfigError(f"{dotted} must be a finite number")
        if direction == "min" and offv < on:
            raise ConfigError(f"offline override loosens {dotted}: {offv} < {on} (P6)")
        if direction == "same" and offv != on:
            raise ConfigError(f"offline override changes deny threshold {dotted} (must stay {on})")
    for cfg in (raw, merged):
        _check_challenge_actions(cfg)
        for dotted in POSITIVE_BUDGETS:
            try:
                v = _get(cfg, dotted)
            except (KeyError, TypeError) as exc:
                raise ConfigError(f"missing config key: {dotted}") from exc
            if isinstance(v, bool) or not isinstance(v, int | float) or not math.isfinite(v) or v <= 0:
                raise ConfigError(f"{dotted} must be a positive finite number of ms, got {v!r}")
    for dotted in ENFORCE_SWITCHES:
        if _switch(raw, dotted) and not _switch(merged, dotted):
            raise ConfigError(f"offline override switches off {dotted} (P6: offline only tightens)")
    try:
        if _get(merged, "liveness.flash.ambient_exception_enabled"):
            raise ConfigError("ambient flash exception must be disabled offline (P6)")
    except KeyError as exc:
        raise ConfigError("missing liveness.flash.ambient_exception_enabled") from exc
