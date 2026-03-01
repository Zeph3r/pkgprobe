"""
Unit tests for EXE subtype detection using structural (PE overlay) heuristics.
Uses synthetic PE blobs; no product-specific fallbacks.
"""
from __future__ import annotations

import pytest

from pkgprobe.trace.subtype import (
    _detect_exe_subtype_from_bytes,
    _pe_end_of_last_section,
    _structural_nsis_signals,
    _has_nsis_structural_evidence,
    detect_exe_subtype_from_bytes,
)


def _make_minimal_pe_with_overlay(stub_size: int, overlay_size: int) -> bytes:
    """
    Build a minimal valid PE that ends at stub_size, then append overlay_size bytes.
    PE: MZ, e_lfanew=64, PE sig, 1 section, section ends at stub_size.
    """
    # DOS header: e_lfanew at 0x3C = 64
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = (64).to_bytes(4, "little")
    # PE at 64
    pe_sig = b"PE\x00\x00"
    coff = bytearray(20)
    coff[0:2] = (0x014C).to_bytes(2, "little")  # Machine IMAGE_FILE_MACHINE_I386
    coff[2:4] = (1).to_bytes(2, "little")  # NumberOfSections
    coff[16:18] = (240).to_bytes(2, "little")  # SizeOfOptionalHeader (PE32+ minimal)
    opt_size = 240
    section_table_offset = 64 + 24 + opt_size  # 328
    # One section: .text, must end at stub_size. PointerToRawData after section headers.
    sec_start = section_table_offset + 40  # first section content starts after one 40-byte header
    size_raw = stub_size - sec_start
    if size_raw < 0:
        size_raw = 0
    section_header = bytearray(40)
    section_header[16:20] = size_raw.to_bytes(4, "little")  # SizeOfRawData
    section_header[20:24] = sec_start.to_bytes(4, "little")  # PointerToRawData
    pe = dos + pe_sig + coff + bytearray(opt_size) + section_header
    # Pad to sec_start, then size_raw bytes, so total stub_size
    if len(pe) < stub_size:
        pe += b"\x00" * (stub_size - len(pe))
    return bytes(pe) + b"\x00" * overlay_size


def test_pe_end_of_last_section_valid():
    """Minimal PE with one section: end_of_last_section = stub_size."""
    stub = 512
    overlay = 1000
    data = _make_minimal_pe_with_overlay(stub, overlay)
    assert data[:2] == b"MZ"
    end = _pe_end_of_last_section(data)
    assert end is not None
    assert end == stub
    assert len(data) == stub + overlay


def test_pe_end_of_last_section_no_pe():
    """Non-PE data returns None."""
    assert _pe_end_of_last_section(b"MZ\x00" * 20) is None
    assert _pe_end_of_last_section(b"PK\x03\x04") is None


def test_structural_signals_has_overlay():
    """Structural signals: has_overlay True when file size > end of last section."""
    data = _make_minimal_pe_with_overlay(400, 300_000)
    has_overlay, overlay_size, stub_size, ratio = _structural_nsis_signals(data)
    assert has_overlay is True
    assert overlay_size == 300_000
    assert stub_size == 400
    assert ratio > 0.99


def test_structural_signals_no_overlay():
    """No overlay: file size equals end of PE."""
    data = _make_minimal_pe_with_overlay(500, 0)
    has_overlay, overlay_size, stub_size, ratio = _structural_nsis_signals(data)
    assert has_overlay is False
    assert overlay_size == 0


def test_nsis_structural_only_detected():
    """Stub + large overlay (no textual markers) -> subtype nsis, confidence 0.65."""
    # Stub 400 bytes, overlay 300KB (>256KB), stub < 512KB
    data = _make_minimal_pe_with_overlay(400, 300 * 1024)
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "nsis"
    assert conf == 0.65


def test_nsis_no_overlay_not_detected():
    """No overlay -> no NSIS from structure; no markers -> None."""
    data = _make_minimal_pe_with_overlay(500, 0)
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype is None
    assert conf == 0.3


def test_nsis_stub_too_large_no_structural():
    """Overlay present but stub too large (>512KB) -> structural heuristic does not fire."""
    # Stub 600KB, overlay 300KB. Stub > 512KB so nsis_structural False.
    stub_size = 600 * 1024
    overlay_size = 300 * 1024
    data = _make_minimal_pe_with_overlay(stub_size, overlay_size)
    has_structural = _has_nsis_structural_evidence(data)
    assert has_structural is False
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype is None
    assert conf == 0.3


def test_nsis_overlay_small_ratio_high_still_structural():
    """Overlay <256KB but ratio >0.70 (tiny stub) -> structural still fires."""
    data = _make_minimal_pe_with_overlay(400, 100 * 1024)
    has_structural = _has_nsis_structural_evidence(data)
    assert has_structural is True
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "nsis"
    assert conf == 0.65


def test_nsis_overlay_small_stub_large_no_structural():
    """Overlay <256KB and stub >512KB -> no structural evidence."""
    data = _make_minimal_pe_with_overlay(600 * 1024, 100 * 1024)
    has_structural = _has_nsis_structural_evidence(data)
    assert has_structural is False
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype is None
    assert conf == 0.3


def test_nsis_structural_plus_textual_combined_confidence():
    """Structural + textual marker -> combined confidence 0.80."""
    data = _make_minimal_pe_with_overlay(400, 300 * 1024)
    # Inject "nsis" weak marker in the overlay part (after stub)
    data = data[:400] + b"nsis" + data[404:]
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "nsis"
    assert conf == 0.80


def test_detect_exe_subtype_from_bytes_no_mz():
    """Public API: no MZ -> (None, 0.0)."""
    assert detect_exe_subtype_from_bytes(b"PK\x03\x04") == (None, 0.0)
