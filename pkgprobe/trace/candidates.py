"""
Candidate silent-switch suggestion for trace-install.

This layer suggests attempt strings for --try-silent. It does not execute
anything and does not depend on TraceSession. Future heuristics (installer
family detection, static inference) can replace or extend this without
changing the execution engine or CLI contract.

TraceSession only ever receives list[str]; it does not know the source.
"""

from __future__ import annotations

from pathlib import Path


EXE_SILENT_SWITCHES = (
    "/S",
    "/silent",
    "/quiet",
    "/qn",
    "/VERYSILENT",
)

MSI_SILENT_SWITCHES = (
    "/qn",
    "/quiet",
    "/passive",
)


def suggest_silent_attempts(installer_path: Path) -> list[str]:
    """
    Suggest a list of silent switch strings to try for the given installer.

    Used when the user passes --try-silent. Does not include "" (interactive);
    try-silent implies "discover a silent configuration", not "try no switches first".

    Future: accept optional static analysis result and return family-specific
    or confidence-ordered candidates without changing the return type or callers.
    """
    path = Path(installer_path)
    suffix = path.suffix.lower()
    if suffix == ".msi":
        return list(MSI_SILENT_SWITCHES)
    return list(EXE_SILENT_SWITCHES)
