"""ProcMon capture/diff tuning profiles for trace runs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

ALLOWED_PROCMON_PROFILES = {"balanced", "low_noise", "high_fidelity"}


@dataclass(frozen=True)
class ProcmonTuning:
    profile: str = "balanced"
    include_processes: list[str] = field(default_factory=list)
    exclude_processes: list[str] = field(default_factory=list)
    include_path_prefixes: list[str] = field(default_factory=list)
    exclude_path_prefixes: list[str] = field(default_factory=list)
    registry_only: bool = False
    baseline_subtraction: bool = True
    strict_pid_tree: bool = False
    noise_strictness: str = "balanced"
    verification_strictness: str = "balanced"


def parse_procmon_tuning(profile: str, raw_json: str) -> ProcmonTuning:
    p = profile if profile in ALLOWED_PROCMON_PROFILES else "balanced"
    tuning = _profile_defaults(p)
    if not raw_json:
        return tuning
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid procmon tuning JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("Procmon tuning JSON must be an object")
    return ProcmonTuning(
        profile=p,
        include_processes=_str_list(data.get("include_processes"), max_items=40),
        exclude_processes=_str_list(data.get("exclude_processes"), max_items=40),
        include_path_prefixes=_str_list(data.get("include_path_prefixes"), max_items=40),
        exclude_path_prefixes=_str_list(data.get("exclude_path_prefixes"), max_items=40),
        registry_only=bool(data.get("registry_only", tuning.registry_only)),
        baseline_subtraction=bool(data.get("baseline_subtraction", tuning.baseline_subtraction)),
        strict_pid_tree=bool(data.get("strict_pid_tree", tuning.strict_pid_tree)),
        noise_strictness=_enum_str(data.get("noise_strictness"), {"conservative", "balanced", "aggressive"}, tuning.noise_strictness),
        verification_strictness=_enum_str(
            data.get("verification_strictness"),
            {"strict", "balanced", "weak_signal_allowed"},
            tuning.verification_strictness,
        ),
    )


def _profile_defaults(profile: str) -> ProcmonTuning:
    if profile == "low_noise":
        return ProcmonTuning(
            profile=profile,
            baseline_subtraction=True,
            strict_pid_tree=True,
            noise_strictness="aggressive",
            verification_strictness="balanced",
        )
    if profile == "high_fidelity":
        return ProcmonTuning(
            profile=profile,
            baseline_subtraction=False,
            strict_pid_tree=False,
            noise_strictness="conservative",
            verification_strictness="balanced",
        )
    return ProcmonTuning(
        profile="balanced",
        baseline_subtraction=True,
        strict_pid_tree=False,
        noise_strictness="balanced",
        verification_strictness="balanced",
    )


def _str_list(v: object, *, max_items: int) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError("Expected list[str]")
    if len(v) > max_items:
        raise ValueError(f"List exceeds max size {max_items}")
    return [x.strip() for x in v if x.strip()]


def _enum_str(v: object, allowed: set[str], default: str) -> str:
    if v is None:
        return default
    if not isinstance(v, str):
        raise ValueError("Expected string enum")
    s = v.strip()
    if s not in allowed:
        raise ValueError(f"Expected one of: {', '.join(sorted(allowed))}")
    return s

