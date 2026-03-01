"""
Aggregator: combines evidence, subtype, and switch policy; returns ordered switch strings.

Weighted inference (base_weight + evidence) is applied in switch_policy;
scores normalized 0-1 and sorted descending.
"""

from __future__ import annotations

from pathlib import Path

from pkgprobe.trace.evidence import family_from_suffix
from pkgprobe.trace.subtype import detect_exe_subtype
from pkgprobe.trace.switch_policy import get_weighted_candidates


def suggest_silent_attempts(path: Path) -> list[str]:
    """
    Suggest silent switch strings for the installer, ordered by weighted score.

    Uses family (msi/exe), EXE sub-type with confidence, and switch policy;
    returns list of switch strings sorted by score descending.
    """
    p = Path(path)
    family = family_from_suffix(p)

    if family == "msi":
        return get_weighted_candidates("msi", p, None, 0.0)
    exe_subtype, exe_confidence = detect_exe_subtype(p)
    return get_weighted_candidates("exe", p, exe_subtype, exe_confidence)
