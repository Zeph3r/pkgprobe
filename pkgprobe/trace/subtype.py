"""
EXE sub-type detection with signal score.

Combines (1) case-insensitive string markers (ASCII + UTF-16LE) and (2) structural
PE overlay heuristics. NSIS packs script into a single EXE with payload appended
after the PE; literal markers may be missing when compression is used, so
structural features (small stub + large overlay) are strong generic signals.

Family remains msi | exe; subtype is nsis | inno | installshield | None.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pkgprobe.trace.evidence import (
    READ_FULL_MAX_SIZE,
    READ_HEAD_SIZE,
    READ_TAIL_SIZE,
    read_head,
    read_tail,
)

ExeSubtype = Literal["nsis", "inno", "installshield"]

# Confidence levels (deterministic)
_CONF_STRONG_MATCH = 0.75  # one strong textual NSIS marker
_CONF_MULTIPLE_MATCH = 0.85  # two+ strong textual markers
_CONF_WEAK_ONLY = 0.6  # weak textual marker only
_CONF_STRUCTURAL = 0.65  # structural overlay heuristic alone (no product-specific)
_CONF_COMBINED = 0.80  # textual + structural both present
_CONF_NO_MARKERS = 0.3

# Structural heuristics: NSIS stub is small, payload (overlay) is appended after PE.
# overlay_size > 256KB and stub_size < 512KB is typical for NSIS installers.
_OVERLAY_MIN_BYTES = 256 * 1024
_STUB_MAX_BYTES = 512 * 1024
_OVERLAY_RATIO_HIGH = 0.70  # overlay_ratio > this is supportive of NSIS

# Heuristic markers: many installers don't have "Nullsoft" in first 512KB;
# we use a curated list of common NSIS/Inno/InstallShield strings.
# Case-insensitive matching; patterns are lowercased at use.

# NSIS strong markers (distinct; multiple -> 0.85, one -> 0.75).
# "nullsoftinst" is the exact header string in NSIS FirstHeader (after FH_SIG).
_NSIS_STRONG: tuple[bytes, ...] = (
    b"nullsoftinst",
    b"nullsoft",
    b"nullsoft install system",
    b"nsis error",
    b"__nsis",
    b"$pluginsdir",
    b".oninit",
    b"setoutpath",
)
# NSIS weak: generic token; only if no strong match -> 0.6 to reduce false positives
_NSIS_WEAK = b"nsis"

# NSIS format signature: FH_SIG 0xDEADBEEF in the appended payload/overlay.
# Try both byte orders; typical NSIS uses little-endian.
_NSIS_MAGIC_SIG_LE = b"\xef\xbe\xad\xde"
_NSIS_MAGIC_SIG_BE = b"\xde\xad\xbe\xef"

# Inno Setup (first match wins among subtypes; we aggregate per subtype)
_INNO_MARKERS: tuple[bytes, ...] = (b"inno setup",)

# InstallShield
_INSTALLSHIELD_MARKERS: tuple[bytes, ...] = (b"installshield",)


def _pe_end_of_last_section(data: bytes) -> int | None:
    """
    Parse PE header and section table to get file offset of end of last section.
    Pure Python, no deps. Returns None if not a valid PE or bounds exceeded.
    """
    if len(data) < 64:
        return None
    # e_lfanew at offset 0x3C
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew < 0 or e_lfanew + 24 >= len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    num_sections = int.from_bytes(data[e_lfanew + 6 : e_lfanew + 8], "little")
    size_optional = int.from_bytes(data[e_lfanew + 20 : e_lfanew + 22], "little")
    section_table = e_lfanew + 24 + size_optional
    if section_table + num_sections * 40 > len(data):
        return None
    end_max = 0
    for i in range(num_sections):
        off = section_table + i * 40
        size_raw = int.from_bytes(data[off + 16 : off + 20], "little")
        ptr_raw = int.from_bytes(data[off + 20 : off + 24], "little")
        if size_raw > 0 and ptr_raw + size_raw <= len(data):
            end_max = max(end_max, ptr_raw + size_raw)
    return end_max if end_max > 0 else None


def _structural_nsis_signals(data: bytes) -> tuple[bool, int, int, float]:
    """
    Compute structural signals for NSIS overlay heuristic.
    Returns (has_overlay, overlay_size, stub_size, overlay_ratio).
    """
    file_size = len(data)
    end_pe = _pe_end_of_last_section(data)
    if end_pe is None or end_pe >= file_size:
        return False, 0, end_pe or 0, 0.0
    overlay_size = file_size - end_pe
    stub_size = end_pe
    ratio = overlay_size / file_size if file_size else 0.0
    return True, overlay_size, stub_size, ratio


def _has_nsis_structural_evidence(data: bytes) -> bool:
    """
    True if PE has overlay pattern typical of NSIS: small stub, large appended payload.
    No product-specific strings; generic structural heuristic.
    """
    has_overlay, overlay_size, stub_size, overlay_ratio = _structural_nsis_signals(data)
    if not has_overlay:
        return False
    if overlay_size > _OVERLAY_MIN_BYTES and stub_size < _STUB_MAX_BYTES:
        return True
    if overlay_ratio >= _OVERLAY_RATIO_HIGH:
        return True
    return False


def _to_lower_ascii(data: bytes) -> bytes:
    """Lowercase A-Z to a-z in place; leave other bytes unchanged for safe scan."""
    return bytes(b + 32 if 0x41 <= b <= 0x5A else b for b in data)


def _utf16le_pattern(pat: bytes) -> bytes:
    """Encode ASCII pattern as UTF-16LE (lowercased) for PE resource/string scan."""
    return pat.decode("ascii").encode("utf-16-le")


def _data_lower_utf16le(data: bytes) -> bytes:
    """Lowercase A-Z in UTF-16LE data (each 2-byte unit); leave other units unchanged."""
    if len(data) < 2:
        return data
    out = bytearray()
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        # UTF-16LE code unit (little-endian)
        code = lo | (hi << 8)
        if 0x41 <= code <= 0x5A:
            code = code + 32
        out.append(code & 0xFF)
        out.append((code >> 8) & 0xFF)
        i += 2
    if i < len(data):
        out.append(data[i])
    return bytes(out)


def _pattern_in_data(pat: bytes, data_lower: bytes, data_raw: bytes) -> bool:
    """True if pattern appears as ASCII (data_lower) or as UTF-16LE in data_raw (case-insensitive)."""
    if pat in data_lower:
        return True
    pat_u16 = _utf16le_pattern(pat)
    data_raw_lower = _data_lower_utf16le(data_raw)
    return pat_u16 in data_raw_lower


def _detect_exe_subtype_from_bytes(data: bytes) -> tuple[ExeSubtype | None, float]:
    """
    Detect EXE sub-type from a byte buffer. MZ is not required here (caller checks).
    Combines (1) NSIS format magic / textual markers and (2) structural overlay heuristics.
    No product-specific fallbacks; structural = small PE stub + large appended payload.
    """
    if len(data) < 2:
        return None, _CONF_NO_MARKERS

    # NSIS format signature in overlay (strongest textual signal)
    if _NSIS_MAGIC_SIG_LE in data or _NSIS_MAGIC_SIG_BE in data:
        return "nsis", _CONF_MULTIPLE_MATCH

    data_lower = _to_lower_ascii(data)

    nsis_strong_found: set[bytes] = set()
    for pat in _NSIS_STRONG:
        if _pattern_in_data(pat, data_lower, data):
            nsis_strong_found.add(pat)
    nsis_weak_found = _pattern_in_data(_NSIS_WEAK, data_lower, data)

    inno_count = sum(1 for p in _INNO_MARKERS if _pattern_in_data(p, data_lower, data))
    ishield_count = sum(1 for p in _INSTALLSHIELD_MARKERS if _pattern_in_data(p, data_lower, data))

    # Structural: PE overlay heuristic (small stub + large payload typical of NSIS)
    nsis_structural = _has_nsis_structural_evidence(data)

    # Prefer Inno then InstallShield then NSIS
    if inno_count > 0:
        return "inno", _CONF_MULTIPLE_MATCH if inno_count > 1 else _CONF_STRONG_MATCH
    if ishield_count > 0:
        return "installshield", _CONF_MULTIPLE_MATCH if ishield_count > 1 else _CONF_STRONG_MATCH

    # NSIS: combine textual and structural evidence; pick best confidence.
    text_conf: float | None = None
    if nsis_strong_found:
        text_conf = _CONF_MULTIPLE_MATCH if len(nsis_strong_found) >= 2 else _CONF_STRONG_MATCH
    elif nsis_weak_found:
        text_conf = _CONF_WEAK_ONLY

    if text_conf is not None and nsis_structural:
        return "nsis", max(text_conf, _CONF_COMBINED)
    if text_conf is not None:
        return "nsis", text_conf
    if nsis_structural:
        return "nsis", _CONF_STRUCTURAL
    return None, _CONF_NO_MARKERS


def detect_exe_subtype_from_bytes(data: bytes) -> tuple[ExeSubtype | None, float]:
    """
    Detect EXE sub-type from pre-read bytes. Caller should pass the full file
    when possible so overlay/payload (e.g. NSIS 0xDEADBEEF) is included.
    Returns (None, 0.0) if data is too short or missing MZ header.
    """
    if len(data) < 2 or data[:2] != b"MZ":
        return None, 0.0
    return _detect_exe_subtype_from_bytes(data)


def detect_exe_subtype(path: Path) -> tuple[ExeSubtype | None, float]:
    """
    Detect EXE sub-type from file: MZ check, then head scan; if no subtype and
    file small (<=8MB) scan full file, else scan head + tail.
    """
    path = Path(path)
    head = read_head(path, READ_HEAD_SIZE)
    if len(head) < 2 or head[:2] != b"MZ":
        return None, 0.0

    subtype, conf = _detect_exe_subtype_from_bytes(head)
    if subtype is not None:
        return subtype, conf

    try:
        size = path.stat().st_size
    except OSError:
        return None, _CONF_NO_MARKERS

    if size <= READ_FULL_MAX_SIZE:
        try:
            with path.open("rb") as f:
                full = f.read()
        except OSError:
            return None, _CONF_NO_MARKERS
        return _detect_exe_subtype_from_bytes(full)

    tail = read_tail(path, READ_TAIL_SIZE)
    combined = head + tail
    return _detect_exe_subtype_from_bytes(combined)
