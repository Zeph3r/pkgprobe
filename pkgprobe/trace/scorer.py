"""
Aggregator: combines evidence, subtype, and switch policy; returns sorted candidates.

Simple linear weighting; sort by weight descending.
"""

from __future__ import annotations

from pathlib import Path

from pkgprobe.trace.evidence import family_from_suffix
from pkgprobe.trace.subtype import detect_exe_subtype
from pkgprobe.trace.switch_policy import SwitchCandidate, get_weighted_candidates


def suggest_silent_attempts(path: Path) -> list[SwitchCandidate]:
    """
    Suggest weighted silent switch candidates for the installer.

    Uses family (msi/exe), EXE sub-type with score, and switch policy;
    returns list sorted by weight descending.
    """
    p = Path(path)
    family = family_from_suffix(p)

    if family == "msi":
        candidates = get_weighted_candidates("msi", p, None, 0.0)
    else:
        exe_subtype, exe_score = detect_exe_subtype(p)
        candidates = get_weighted_candidates(
            "exe", p, exe_subtype, exe_score
        )

    return sorted(candidates, key=lambda c: c.weight, reverse=True)
