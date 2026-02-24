#!/usr/bin/env python
"""
Verify that __version__ is the single source of truth and matches CLI --version.
Run from project root: uv run python scripts/check_version.py
"""
from __future__ import annotations

import subprocess
import sys


def main() -> int:
    from pkgprobe import __version__

    print(f"1. pkgprobe.__version__ = {__version__!r}")

    result = subprocess.run(
        [sys.executable, "-m", "pkgprobe.cli", "--version"],
        capture_output=True,
        text=True,
        cwd=None,
    )
    cli_version = result.stdout.strip() if result.returncode == 0 else None
    if result.returncode != 0:
        print(f"2. pkgprobe --version failed: {result.stderr}")
        return 1
    print(f"2. pkgprobe --version = {cli_version!r}")

    if __version__ != cli_version:
        print(f"ERROR: __version__ ({__version__!r}) != CLI output ({cli_version!r})")
        return 1
    print("3. Banner and CLI both use the same version.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
