"""
Unit tests for EXE subtype detection (marker matching, confidence, MZ).
Uses synthetic byte buffers; no real installer files required.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from pkgprobe.trace.subtype import _detect_exe_subtype_from_bytes, detect_exe_subtype


def test_mz_required():
    """Buffer missing MZ header -> (None, 0.0) from path; from_bytes returns generic."""
    assert _detect_exe_subtype_from_bytes(b"PK\x03\x04")[0] is None
    assert _detect_exe_subtype_from_bytes(b"PK\x03\x04")[1] == 0.3


def test_no_markers():
    """Buffer with MZ but no known markers -> (None, 0.3)."""
    data = b"MZ" + b"\x00" * 100 + b"some random data"
    assert _detect_exe_subtype_from_bytes(data) == (None, 0.3)


def test_nsis_error_strong():
    """Buffer contains 'NSIS Error' -> (nsis, 0.75)."""
    data = b"MZ" + b"NSIS Error" + b"\x00" * 50
    assert _detect_exe_subtype_from_bytes(data) == ("nsis", 0.75)


def test_nsis_multiple_strong():
    """Buffer contains __NSIS and $PLUGINSDIR -> (nsis, 0.85)."""
    data = b"MZ" + b"__NSIS" + b"xyz" + b"$PLUGINSDIR" + b"\x00" * 50
    assert _detect_exe_subtype_from_bytes(data) == ("nsis", 0.85)


def test_inno_setup():
    """Buffer contains 'Inno Setup' -> (inno, 0.75)."""
    data = b"MZ" + b"Inno Setup" + b"\x00" * 50
    assert _detect_exe_subtype_from_bytes(data) == ("inno", 0.75)


def test_installshield():
    """Buffer contains 'InstallShield' -> (installshield, 0.75)."""
    data = b"MZ" + b"InstallShield" + b"\x00" * 50
    assert _detect_exe_subtype_from_bytes(data) == ("installshield", 0.75)


def test_case_insensitive_nsis():
    """Case-insensitive: 'NULLSOFT INSTALL SYSTEM' matches NSIS (one or more strong -> nsis, conf >= 0.75)."""
    data = b"MZ" + b"NULLSOFT INSTALL SYSTEM" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "nsis"
    assert conf >= 0.75


def test_nsis_weak_only():
    """Only weak marker 'nsis' -> (nsis, 0.6)."""
    data = b"MZ" + b"something nsis here" + b"\x00" * 50
    assert _detect_exe_subtype_from_bytes(data) == ("nsis", 0.6)


def test_nsis_utf16le_detected():
    """NSIS marker stored as UTF-16LE (common in PE) is detected."""
    # "NSIS Error" as UTF-16LE
    nsis_utf16 = "NSIS Error".encode("utf-16-le")
    data = b"MZ" + b"\x00" * 200 + nsis_utf16 + b"\x00" * 100
    assert _detect_exe_subtype_from_bytes(data) == ("nsis", 0.75)


def test_nsis_deadbeef_magic():
    """NSIS format signature 0xDEADBEEF (in overlay) is detected as NSIS with high confidence."""
    # Simulate PE stub + overlay: magic appears in "tail" region
    overlay = b"\x00\x00\x00\x00\xef\xbe\xad\xde" + b"NullsoftInst" + b"\x00" * 100
    data = b"MZ" + b"\x00" * 500_000 + overlay  # head + overlay
    assert _detect_exe_subtype_from_bytes(data) == ("nsis", 0.85)


def test_no_product_fallback():
    """Product string alone (e.g. 7-Zip) without NSIS markers or valid PE overlay -> (None, 0.3)."""
    data = b"MZ" + b"\x00" * 1000 + b"7-Zip 26.00" + b"\x00" * 500
    assert _detect_exe_subtype_from_bytes(data) == (None, 0.3)


def test_detect_exe_subtype_path_no_mz(tmp_path: Path) -> None:
    """File without MZ -> (None, 0.0)."""
    f = tmp_path / "a.exe"
    f.write_bytes(b"not MZ")
    assert detect_exe_subtype(f) == (None, 0.0)


def test_detect_exe_subtype_path_nsis_in_head(tmp_path: Path) -> None:
    """File with MZ + NSIS Error in first bytes -> (nsis, 0.75)."""
    f = tmp_path / "a.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100 + b"NSIS Error" + b"\x00" * 1000)
    assert detect_exe_subtype(f) == ("nsis", 0.75)
