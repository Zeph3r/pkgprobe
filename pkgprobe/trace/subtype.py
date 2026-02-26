"""
EXE sub-type detection with signal score.

Uses evidence (binary head, MZ, string scan) to return (subtype, confidence).
Family remains msi | exe; subtype is nsis | inno | installshield | None.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pkgprobe.trace.evidence import read_head

ExeSubtype = Literal["nsis", "inno", "installshield"]

# Signatures for crude string scan (first match wins)
_SIGNATURES: list[tuple[bytes, ExeSubtype]] = [
    (b"Nullsoft", "nsis"),
    (b"Inno Setup", "inno"),
    (b"InstallShield", "installshield"),
]

# Confidence when a signature is found (0–1)
_SUBTYPE_CONFIDENCE = 0.9


def detect_exe_subtype(path: Path) -> tuple[ExeSubtype | None, float]:
    """
    Detect EXE sub-type from binary evidence and return (subtype, score).

    Checks PE magic (MZ), then scans head for Nullsoft / Inno Setup / InstallShield.
    Returns (subtype, confidence in 0–1) or (None, 0.0) for generic exe.
    """
    head = read_head(path)
    if len(head) < 2 or head[:2] != b"MZ":
        return None, 0.0
    for sig, subtype in _SIGNATURES:
        if sig in head:
            return subtype, _SUBTYPE_CONFIDENCE
    return None, 0.0
