"""
Binary and filename evidence for installer family/subtype.

Reads file head and path metadata only. No interpretation;
subtype and switch policy layers consume this.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

InstallerFamily = Literal["msi", "exe"]

# How much of the file to read for signature scan (bytes)
READ_HEAD_SIZE = 512 * 1024


def read_head(path: Path, size: int = READ_HEAD_SIZE) -> bytes:
    """Read the first size bytes of path. Returns empty bytes on any error."""
    try:
        with path.open("rb") as f:
            return f.read(size)
    except OSError:
        return b""


def family_from_suffix(path: Path) -> InstallerFamily:
    """Installer family from path suffix only (msi vs exe)."""
    p = Path(path)
    if p.suffix.lower() == ".msi":
        return "msi"
    return "exe"


def filename_lower(path: Path) -> str:
    """Filename only, lowercased, for token checks."""
    return Path(path).name.lower()


def has_filename_token(path: Path, token: str) -> bool:
    """True if token appears in filename (case-insensitive)."""
    return token.lower() in filename_lower(path)
