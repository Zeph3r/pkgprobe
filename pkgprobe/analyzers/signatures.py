"""
EXE installer-type detection for the analyze command.

EXE subtype detection is delegated to pkgprobe.trace.subtype.detect_exe_subtype()
so that analyze, trace-install, and switch suggestion share one authoritative
detector. No duplicated NSIS/Inno/InstallShield string logic lives here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from pkgprobe.trace.subtype import detect_exe_subtype_from_bytes


@dataclass(frozen=True)
class SignatureHit:
    name: str
    confidence: float
    evidence: str


# Map subtype.py result to analyze's installer_type label and optional hit
_SUBTYPE_TO_LABEL: dict[str, str] = {
    "nsis": "NSIS",
    "inno": "Inno Setup",
    "installshield": "InstallShield",
}


def detect_installer_type(path: Path, exe_bytes: bytes) -> Tuple[str, float, List[SignatureHit]]:
    """
    Detect EXE installer type by delegating to subtype using the exact bytes
    already read (so overlay/payload is included). Returns (installer_type,
    confidence, hits) for backward compatibility with analyze_exe and InstallPlan.
    """
    subtype, confidence = detect_exe_subtype_from_bytes(exe_bytes)
    if subtype is not None:
        label = _SUBTYPE_TO_LABEL.get(subtype, "Unknown EXE installer")
        hits = [SignatureHit(label, confidence, f"Subtype from trace.subtype: {subtype}")]
        return (label, confidence, hits)
    return ("Unknown EXE installer", confidence, [])
