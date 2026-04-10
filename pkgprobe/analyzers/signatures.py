"""
EXE installer-type detection for the analyze command.

EXE subtype detection is delegated to pkgprobe.trace.subtype so that analyze,
trace-install, and switch suggestion share one authoritative detector.
No duplicated detection logic lives here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from pkgprobe.models import Evidence, FamilyResult
from pkgprobe.trace.subtype import (
    FamilyVerdict,
    detect_exe_subtype_from_bytes,
    detect_exe_subtype_full,
)


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
    "burn": "WiX Burn",
    "squirrel": "Squirrel",
    "msix_wrapper": "MSIX/AppX Wrapper",
}


def _verdict_to_family_result(verdict: FamilyVerdict) -> FamilyResult | None:
    """Convert a FamilyVerdict into the Pydantic FamilyResult for InstallPlan."""
    if verdict.chosen is None:
        return None
    evidence = [
        Evidence(kind=e.strength, detail=f"marker: {e.marker}")
        for e in verdict.chosen.evidence
    ]
    alternatives = [
        {
            "family": alt.family,
            "confidence": alt.confidence,
            "evidence": [{"marker": e.marker, "strength": e.strength} for e in alt.evidence],
            "rejection_reason": alt.rejection_reason,
        }
        for alt in verdict.alternatives
    ]
    return FamilyResult(
        family=verdict.chosen.family,
        confidence=verdict.chosen.confidence,
        confidence_tier=verdict.confidence_tier,
        evidence=evidence,
        alternatives_considered=alternatives,
    )


def detect_installer_type(
    path: Path, exe_bytes: bytes,
) -> Tuple[str, float, List[SignatureHit]]:
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


def detect_installer_type_full(
    path: Path, exe_bytes: bytes,
) -> Tuple[str, float, List[SignatureHit], FamilyResult | None]:
    """
    Extended detection returning the same tuple plus a FamilyResult with
    evidence trail and rejected alternatives for InstallPlan.family_result.
    """
    verdict = detect_exe_subtype_full(exe_bytes)
    family_result = _verdict_to_family_result(verdict)

    if verdict.chosen is not None:
        label = _SUBTYPE_TO_LABEL.get(verdict.chosen.family, "Unknown EXE installer")
        confidence = verdict.chosen.confidence
        hits = [SignatureHit(label, confidence, f"Subtype from trace.subtype: {verdict.chosen.family}")]
        return (label, confidence, hits, family_result)

    return ("Unknown EXE installer", 0.3, [], family_result)
