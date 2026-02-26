"""
Candidate silent-switch suggestion for trace-install.

Public facade over evidence → subtype → switch_policy → scorer.
TraceSession receives list[str]; CLI maps SwitchCandidate.switch for that.
"""

from __future__ import annotations

from pathlib import Path

from pkgprobe.trace.evidence import InstallerFamily, family_from_suffix
from pkgprobe.trace.scorer import suggest_silent_attempts
from pkgprobe.trace.subtype import detect_exe_subtype
from pkgprobe.trace.switch_policy import SwitchCandidate

__all__ = [
    "InstallerFamily",
    "SwitchCandidate",
    "detect_installer_family",
    "detect_exe_subtype",
    "suggest_silent_attempts",
]


def detect_installer_family(installer_path: Path) -> InstallerFamily:
    """Detect installer family from path (msi | exe). Uses suffix only."""
    return family_from_suffix(Path(installer_path))
