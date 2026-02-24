"""
Banner module for the pkgprobe CLI.

Displays a branded startup banner with ASCII art logo, tagline,
version, and GitHub attribution using Rich for colored output.

Smart detection: banner is only shown when output is a TTY,
not in CI, and --quiet was not passed.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

from pkgprobe import __version__


def should_show_banner(quiet: bool = False) -> bool:
    """
    Determine whether the banner should be shown.

    Banner is suppressed when:
    - quiet is True (user passed --quiet/-q)
    - stdout is not a terminal (e.g. output is piped)
    - CI environment variable is set (e.g. GitHub Actions, GitLab CI)

    Args:
        quiet: True if user passed --quiet/-q.

    Returns:
        True if the banner should be displayed, False otherwise.
    """
    if quiet:
        return False
    if not sys.stdout.isatty():
        return False
    ci = os.environ.get("CI", "").strip().lower()
    if ci in ("true", "1", "yes"):
        return False
    return True


def show_banner(version: Optional[str] = None) -> None:
    """
    Print the pkgprobe CLI banner to stdout.

    Uses Rich for colored output. If version is not provided,
    uses pkgprobe.__version__ (single source of truth).

    Args:
        version: Optional version string. If None, uses pkgprobe.__version__.
    """
    from rich.console import Console
    from rich.style import Style

    if version is None:
        version = __version__

    console = Console()

    # ASCII art logo: "pkg" in white, "robe" in orange (exact char split per line)
    white_parts = [
        "        _",
        "  _ __ | | ____ _ ",
        " | '_ \\| |/ / _` |",
        " | |_) |   < (_| |",
        " | .__/|_|\\_\\__, |",
        " |_|        |___/",
    ]
    orange_parts = [
        "                         _          ",  # 25 spaces so "_" aligns above 'e' not 'r'
        " _ __  _ __ ___ | |__   ___ ",
        "| '_ \\| '__/ _ \\| '_ \\ / _ \\",
        "| |_) | | | (_) | |_) |  __/",
        "| .__/|_|  \\___/|_.__/ \\___/",
        "|_|                         ",
    ]

    white_style = Style(color="white")
    orange_style = Style(color="#FF8C00")  # dark orange (RGB), avoids green on some terminals
    for w, o in zip(white_parts, orange_parts):
        console.print(w, end="", style=white_style)
        console.print(o, style=orange_style)
    console.print()

    # Tagline: white, dim
    tagline = "Package Intelligence for Windows Installers"
    console.print(tagline, style=Style(color="white", dim=True))
    console.print()

    # Version and GitHub: dim gray
    dim_gray = Style(dim=True)
    console.print(f"  v{version}", style=dim_gray)
    console.print("  @Zeph3r on GitHub", style=dim_gray)
    console.print("  https://github.com/Zeph3r/pkgprobe", style=dim_gray)
    console.print()
