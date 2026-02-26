"""
Mapping from subtype (and filename evidence) to weighted switch candidates.

Each candidate has switch, weight, and reason for traceability and sorting.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pkgprobe.trace.evidence import has_filename_token


@dataclass(frozen=True)
class SwitchCandidate:
    """A single silent-switch suggestion with weight and reasoning."""
    switch: str
    weight: float
    reason: str


# Subtype-specific weighted lists: (switch, weight, reason)
_NSIS: list[tuple[str, float, str]] = [
    ("/S", 0.95, "nsis_primary"),
    ("/silent", 0.6, "nsis_fallback"),
    ("/quiet", 0.5, "nsis_fallback"),
    ("/qn", 0.4, "nsis_fallback"),
    ("/VERYSILENT", 0.35, "nsis_fallback"),
]
_INNO: list[tuple[str, float, str]] = [
    ("/VERYSILENT", 0.95, "inno_primary"),
    ("/SILENT", 0.85, "inno_primary"),
    ("/silent", 0.6, "inno_fallback"),
    ("/quiet", 0.5, "inno_fallback"),
    ("/S", 0.4, "inno_fallback"),
]
_INSTALLSHIELD: list[tuple[str, float, str]] = [
    ("/quiet", 0.9, "installshield_primary"),
    ("/s", 0.8, "installshield_primary"),
    ("/S", 0.6, "installshield_fallback"),
    ("/silent", 0.5, "installshield_fallback"),
    ("/qn", 0.4, "installshield_fallback"),
    ("/VERYSILENT", 0.35, "installshield_fallback"),
]
_MSI: list[tuple[str, float, str]] = [
    ("/qn", 0.95, "msi_primary"),
    ("/quiet", 0.9, "msi_primary"),
    ("/passive", 0.7, "msi_fallback"),
]
_GENERIC_EXE: list[tuple[str, float, str]] = [
    ("/S", 0.85, "generic_primary"),
    ("/silent", 0.6, "generic_fallback"),
    ("/quiet", 0.5, "generic_fallback"),
    ("/qn", 0.4, "generic_fallback"),
    ("/VERYSILENT", 0.35, "generic_fallback"),
]


def _to_candidates(items: list[tuple[str, float, str]]) -> list[SwitchCandidate]:
    return [SwitchCandidate(s, w, r) for s, w, r in items]


def get_weighted_candidates(
    family: Literal["msi", "exe"],
    path: Path,
    exe_subtype: Literal["nsis", "inno", "installshield"] | None,
    exe_subtype_score: float,
) -> list[SwitchCandidate]:
    """
    Return weighted switch candidates for the given family and (for exe) subtype.

    Filename evidence (e.g. bootstrapper) can boost /quiet. Results are not
    sorted here; scorer sorts by weight.
    """
    if family == "msi":
        return _to_candidates(_MSI)

    if exe_subtype == "nsis":
        candidates = _to_candidates(_NSIS)
    elif exe_subtype == "inno":
        candidates = _to_candidates(_INNO)
    elif exe_subtype == "installshield":
        candidates = _to_candidates(_INSTALLSHIELD)
    else:
        candidates = _to_candidates(_GENERIC_EXE)

    # Bootstrapper-style installers often respect /quiet: boost its weight
    if has_filename_token(path, "bootstrapper"):
        candidates = [
            SwitchCandidate(c.switch, c.weight + 0.15 if c.switch == "/quiet" else 0.0, c.reason)
            if c.switch == "/quiet" else c
            for c in candidates
        ]
    return candidates
