"""
Built-in filters for ProcMon-derived diffs.

VM traces include VMware Tools, ProcMon itself, Defender, session noise, etc.
These heuristics drop obvious non-installer signal before InstallPlan / manifest.
"""

from __future__ import annotations

from typing import FrozenSet, Optional

# Process image names (lowercase, may include extension).
_NOISE_PROCESS_NAMES: FrozenSet[str] = frozenset(
    {
        "procmon.exe",
        "procmon64.exe",
        "procmon64a.exe",
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vmwaretoolboxcmd.exe",
        "vmacthlp.exe",
        "msmpeng.exe",
        "csrss.exe",
        "system",
        "registry",  # kernel registry thread in some captures
    }
)

# Normalized path prefixes (see _norm_path).
_NOISE_FILE_PREFIXES: tuple[str, ...] = (
    r"c:\program files\vmware",
    r"c:\program files (x86)\vmware",
    r"c:\program files\common files\vmware",
    r"c:\program files (x86)\common files\vmware",
    r"c:\trace",
    r"c:\windows\system32\drivers",
)

# Substrings for registry paths (normalized: backslashes, lowercased).
_NOISE_REGISTRY_SUBSTRINGS: tuple[str, ...] = (
    r"\software\vmware",
    r"\system\currentcontrolset\services\vmware",
    r"\software\microsoft\windows\currentversion\installer\folders\c:\program files\vmware",
)


def _norm_path(p: str) -> str:
    return p.replace("/", "\\").strip().lower()


def _norm_process(name: Optional[str]) -> str:
    if not name:
        return ""
    return name.strip().lower()


def should_skip_file_event(process_name: Optional[str], path: str, strictness: str = "balanced") -> bool:
    """Return True if this file path should not appear in the diff."""
    proc = _norm_process(process_name)
    if proc and proc in _NOISE_PROCESS_NAMES:
        return True
    np = _norm_path(path)
    if not np:
        return True
    prefixes = list(_NOISE_FILE_PREFIXES)
    if strictness == "aggressive":
        prefixes.extend(
            [
                r"c:\windows\temp",
                r"c:\windows\prefetch",
                r"c:\programdata\microsoft\search",
            ]
        )
    elif strictness == "conservative":
        # Keep only VM/process-specific file skips.
        prefixes = [r"c:\program files\vmware", r"c:\program files (x86)\vmware", r"c:\trace"]
    for prefix in prefixes:
        if np.startswith(prefix):
            return True
    # Typical disposable-VM guest profile noise (adjust if your guest username differs).
    if r"\guest\appdata" in np:
        return True
    return False


def should_skip_registry_event(process_name: Optional[str], path: str, strictness: str = "balanced") -> bool:
    """Return True if this registry path should not appear in the diff."""
    proc = _norm_process(process_name)
    if proc and proc in _NOISE_PROCESS_NAMES:
        return True
    np = _norm_path(path)
    if not np:
        return True
    subs = list(_NOISE_REGISTRY_SUBSTRINGS)
    if strictness == "aggressive":
        subs.extend(
            [
                r"\software\microsoft\windows\currentversion\group policy",
                r"\software\microsoft\windows\currentversion\explorer",
            ]
        )
    elif strictness == "conservative":
        subs = [r"\software\vmware", r"\system\currentcontrolset\services\vmware"]
    for sub in subs:
        if sub in np:
            return True
    return False
