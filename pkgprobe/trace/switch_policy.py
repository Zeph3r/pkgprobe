"""
Mapping from family/subtype to weighted switch candidates.

Uses internal weighted inference: base_weight + evidence (subtype, filename).
Scores normalized 0-1, sorted descending; returns list of switch strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pkgprobe.trace.evidence import has_filename_token
from pkgprobe.trace.weighting import DetectionEvidence, _WeightedSwitchCandidate


@dataclass(frozen=True)
class SwitchCandidate:
    """Public: single silent-switch suggestion (weight/reason for future CLI display)."""
    switch: str
    weight: float
    reason: str

# Base weights per policy (deterministic)
_MSI_BASE: list[tuple[str, float]] = [
    ("/qn", 0.8),
    ("/quiet", 0.7),
    ("/passive", 0.6),
]
_NSIS_BASE: list[tuple[str, float]] = [
    ("/S", 0.75),
    ("/silent", 0.5),
    ("/quiet", 0.4),
    ("/qn", 0.3),
    ("/VERYSILENT", 0.2),
]
_INNO_BASE: list[tuple[str, float]] = [
    ("/VERYSILENT", 0.75),
    ("/SILENT", 0.7),
    ("/silent", 0.5),
    ("/quiet", 0.4),
    ("/S", 0.3),
]
_INSTALLSHIELD_BASE: list[tuple[str, float]] = [
    ("/quiet", 0.75),
    ("/s", 0.7),
    ("/S", 0.5),
    ("/silent", 0.4),
    ("/qn", 0.3),
    ("/VERYSILENT", 0.2),
]
_GENERIC_EXE_BASE: list[tuple[str, float]] = [
    ("/S", 0.6),
    ("/silent", 0.5),
    ("/quiet", 0.45),
    ("/qn", 0.3),
    ("/VERYSILENT", 0.2),
]

# Subtype boost: add evidence to primary switch only (weight = subtype_confidence * 0.2)
_SUBTYPE_PRIMARY_SWITCH: dict[str, str] = {
    "nsis": "/S",
    "inno": "/VERYSILENT",
    "installshield": "/quiet",
}
_SUBTYPE_BOOST_FACTOR = 0.2


def _build_candidates(
    base_list: list[tuple[str, float]],
    path: Path,
    exe_subtype: Literal["nsis", "inno", "installshield"] | None,
    exe_subtype_confidence: float,
) -> list[_WeightedSwitchCandidate]:
    """Build weighted candidates with evidence; subtype and filename boosts applied."""
    candidates: list[_WeightedSwitchCandidate] = []
    for switch, base_weight in base_list:
        evidence: list[DetectionEvidence] = []

        if exe_subtype and exe_subtype_confidence > 0 and _SUBTYPE_PRIMARY_SWITCH.get(exe_subtype) == switch:
            evidence.append(
                DetectionEvidence(source="subtype", value=exe_subtype, weight=exe_subtype_confidence * _SUBTYPE_BOOST_FACTOR)
            )

        if switch == "/quiet" and has_filename_token(path, "bootstrapper"):
            evidence.append(DetectionEvidence(source="filename", value="bootstrapper", weight=0.15))

        candidates.append(_WeightedSwitchCandidate(switch=switch, base_weight=base_weight, evidence=evidence))
    return candidates


def _normalize_scores(candidates: list[_WeightedSwitchCandidate]) -> list[_WeightedSwitchCandidate]:
    """Min-max normalize scores to 0.0-1.0. In place we don't mutate; return new list with normalized scores stored for sort."""
    if not candidates:
        return []
    raw_scores = [c.score() for c in candidates]
    lo, hi = min(raw_scores), max(raw_scores)
    if hi <= lo:
        return candidates
    # Keep same order, just use normalized score for sorting; we sort by score desc
    scored = [(c, (c.score() - lo) / (hi - lo)) for c in candidates]
    scored.sort(key=lambda x: -x[1])
    return [x[0] for x in scored]


def get_weighted_candidates(
    family: Literal["msi", "exe"],
    path: Path,
    exe_subtype: Literal["nsis", "inno", "installshield"] | None,
    exe_subtype_confidence: float,
) -> list[str]:
    """
    Build weighted candidates, score, normalize to 0-1, sort descending by score.
    Returns list of switch strings for backward-compatible API.
    """
    if family == "msi":
        base_list = _MSI_BASE
    elif exe_subtype == "nsis":
        base_list = _NSIS_BASE
    elif exe_subtype == "inno":
        base_list = _INNO_BASE
    elif exe_subtype == "installshield":
        base_list = _INSTALLSHIELD_BASE
    else:
        base_list = _GENERIC_EXE_BASE

    candidates = _build_candidates(base_list, path, exe_subtype, exe_subtype_confidence)
    ordered = _normalize_scores(candidates)
    return [c.switch for c in ordered]
