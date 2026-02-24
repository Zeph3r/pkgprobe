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
    from rich.text import Text

    if version is None:
        version = __version__

    console = Console()

    # Each row is (white_segment, orange_segment).
    # White lines are padded to a fixed width (20 chars) so orange always
    # starts at the same column regardless of Rich's internal cursor tracking.
    WHITE_WIDTH = 20

    logo_rows = [
        ("        _           ", "                         _          "),
        ("  _ __ | | ____ _   ", " _ __  _ __ ___ | |__   ___ "),
        (" | '_ \\| |/ / _` |  ", "| '_ \\| '__/ _ \\| '_ \\ / _ \\"),
        (" | |_) |   < (_| |  ", "| |_) | | | (_) | |_) |  __/"),
        (" | .__/|_|\\_\\__, |  ", "| .__/|_|  \\___/|_.__/ \\___/"),
        (" |_|        |___/   ", "|_|                         "),
    ]

    for white_seg, orange_seg in logo_rows:
        line = Text()
        line.append(white_seg.ljust(WHITE_WIDTH), style="white")
        line.append(orange_seg, style="#FF8C00")
        console.print(line)

    console.print()

    # Tagline
    console.print(
        "Package Intelligence for Windows Installers",
        style="white dim",
    )
    console.print()

    # Version and GitHub
    console.print(f"  v{version}", style="dim")
    console.print("  @Zeph3r on GitHub", style="dim")
    console.print("  https://pkgprobe.io", style="dim")
    console.print()