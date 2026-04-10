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


# ── Burn / WiX ──────────────────────────────────────────────────────────


def test_burn_wixburn_strong():
    """'.wixburn' is a strong Burn marker."""
    data = b"MZ" + b"\x00" * 100 + b".wixburn" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "burn"
    assert conf == 0.75


def test_burn_multiple_strong():
    """Two strong Burn markers -> 0.85."""
    data = b"MZ" + b"WixBundleManifest" + b"\x00" * 20 + b"BootstrapperApplication" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "burn"
    assert conf == 0.85


def test_burn_weak_only():
    """Only weak 'wix' without NSIS evidence -> burn at 0.6."""
    data = b"MZ" + b"something wix based" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "burn"
    assert conf == 0.6


def test_burn_wixstdba():
    """wixstdba (standard bootstrapper application) marker."""
    data = b"MZ" + b"\x00" * 50 + b"WixStdBA" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "burn"
    assert conf == 0.75


# ── Squirrel ─────────────────────────────────────────────────────────────


def test_squirrel_strong():
    """'squirreltemp' is a strong Squirrel marker."""
    data = b"MZ" + b"\x00" * 100 + b"SquirrelTemp" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "squirrel"
    assert conf == 0.75


def test_squirrel_multiple_strong():
    """Two+ strong Squirrel markers -> 0.85."""
    data = b"MZ" + b"squirreltemp" + b"\x00" * 10 + b"squirrel-install" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "squirrel"
    assert conf == 0.85


def test_squirrel_weak_only():
    """Only 'squirrel' string without NSIS markers -> squirrel at 0.6."""
    data = b"MZ" + b"some squirrel thing" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "squirrel"
    assert conf == 0.6


# ── MSIX / AppX Wrapper ─────────────────────────────────────────────────


def test_msix_appxmanifest():
    """'AppxManifest.xml' -> msix_wrapper."""
    data = b"MZ" + b"\x00" * 100 + b"AppxManifest.xml" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "msix_wrapper"
    assert conf == 0.75


def test_msix_multiple_markers():
    """Two MSIX markers -> 0.85."""
    data = b"MZ" + b"AppxManifest.xml" + b"\x00" * 10 + b"AppxBlockMap.xml" + b"\x00" * 50
    subtype, conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "msix_wrapper"
    assert conf == 0.85


# ── Priority ordering ───────────────────────────────────────────────────


def test_inno_beats_burn():
    """Inno marker + burn marker -> Inno wins (higher priority)."""
    data = b"MZ" + b"Inno Setup" + b"\x00" * 10 + b".wixburn" + b"\x00" * 50
    subtype, _conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "inno"


def test_burn_beats_squirrel():
    """Burn strong marker + squirrel strong marker -> Burn wins."""
    data = b"MZ" + b".wixburn" + b"\x00" * 10 + b"SquirrelTemp" + b"\x00" * 50
    subtype, _conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "burn"


def test_squirrel_beats_msix():
    """Squirrel strong + MSIX marker -> Squirrel wins."""
    data = b"MZ" + b"SquirrelTemp" + b"\x00" * 10 + b"AppxManifest.xml" + b"\x00" * 50
    subtype, _conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "squirrel"


def test_msix_beats_nsis_weak():
    """MSIX marker + only weak NSIS -> MSIX wins."""
    data = b"MZ" + b"AppxManifest.xml" + b"\x00" * 10 + b"nsis" + b"\x00" * 50
    subtype, _conf = _detect_exe_subtype_from_bytes(data)
    assert subtype == "msix_wrapper"


# ── FamilyVerdict tests ─────────────────────────────────────────────────

from pkgprobe.trace.subtype import detect_exe_subtype_full, FamilyVerdict


class TestFamilyVerdict:
    def test_verdict_no_mz(self):
        """Non-MZ data -> empty verdict."""
        verdict = detect_exe_subtype_full(b"PK\x03\x04something")
        assert verdict.chosen is None
        assert verdict.alternatives == []
        assert verdict.confidence_tier == "low"

    def test_verdict_no_markers(self):
        """MZ with no markers -> chosen is None, tier is low."""
        data = b"MZ" + b"\x00" * 100 + b"random data"
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is None
        assert verdict.confidence_tier == "low"

    def test_verdict_nsis_strong_has_evidence(self):
        """NSIS strong marker produces evidence trail."""
        data = b"MZ" + b"NSIS Error" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "nsis"
        assert verdict.confidence_tier == "high"
        markers = [e.marker for e in verdict.chosen.evidence]
        assert "nsis error" in markers

    def test_verdict_alternatives_populated(self):
        """When multiple families have evidence, alternatives are populated."""
        data = b"MZ" + b"Inno Setup" + b"\x00" * 10 + b".wixburn" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "inno"
        alt_families = {a.family for a in verdict.alternatives}
        assert "burn" in alt_families
        burn_alt = next(a for a in verdict.alternatives if a.family == "burn")
        assert burn_alt.rejected is True
        assert burn_alt.rejection_reason is not None

    def test_verdict_confidence_tier_high(self):
        """Strong marker -> high tier."""
        data = b"MZ" + b"Inno Setup" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.confidence_tier == "high"

    def test_verdict_confidence_tier_medium(self):
        """Weak marker -> medium tier (0.6)."""
        data = b"MZ" + b"something nsis here" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.confidence_tier == "medium"

    def test_verdict_confidence_tier_low(self):
        """No markers -> low tier."""
        data = b"MZ" + b"\x00" * 100 + b"completely unrelated"
        verdict = detect_exe_subtype_full(data)
        assert verdict.confidence_tier == "low"

    def test_burn_confidence_capped_single_strong(self):
        """Burn single strong marker capped at 0.70 (not 0.75)."""
        data = b"MZ" + b"\x00" * 50 + b".wixburn" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "burn"
        assert verdict.chosen.confidence == 0.70

    def test_burn_confidence_capped_multiple_strong(self):
        """Burn multiple strong markers capped at 0.80 (not 0.85)."""
        data = (
            b"MZ" + b"WixBundleManifest" + b"\x00" * 10
            + b"BootstrapperApplication" + b"\x00" * 50
        )
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "burn"
        assert verdict.chosen.confidence == 0.80

    def test_verdict_evidence_strength_labels(self):
        """Evidence items carry correct strength labels."""
        data = b"MZ" + b".wixburn" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert all(e.strength == "strong" for e in verdict.chosen.evidence)

    def test_verdict_weak_evidence_label(self):
        """Weak-only detection has 'weak' strength in evidence."""
        data = b"MZ" + b"something wix based" + b"\x00" * 50
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "burn"
        assert any(e.strength == "weak" for e in verdict.chosen.evidence)

    def test_verdict_nsis_structural_evidence(self):
        """NSIS structural overlay produces structural-strength evidence."""
        # Build a synthetic PE: e_lfanew at offset 0x3C (60), pointing to 0x80
        stub = bytearray(b"\x00" * 512)
        stub[0:2] = b"MZ"
        pe_offset = 0x80
        stub[0x3C:0x40] = pe_offset.to_bytes(4, "little")
        # PE signature at pe_offset
        stub[pe_offset:pe_offset + 4] = b"PE\x00\x00"
        # COFF: 1 section, SizeOfOptionalHeader = 0
        stub[pe_offset + 6:pe_offset + 8] = (1).to_bytes(2, "little")
        stub[pe_offset + 20:pe_offset + 22] = (0).to_bytes(2, "little")
        # Section table starts at pe_offset + 24
        sec = pe_offset + 24
        stub[sec:sec + 8] = b".text\x00\x00\x00"
        # SizeOfRawData = 0x100, PointerToRawData = 0x100
        stub[sec + 16:sec + 20] = (0x100).to_bytes(4, "little")
        stub[sec + 20:sec + 24] = (0x100).to_bytes(4, "little")
        # Pad stub to end-of-section = 0x100 + 0x100 = 0x200 (512 bytes)
        pe_data = bytes(stub).ljust(0x200, b"\x00")
        # Overlay >256KB triggers structural heuristic
        overlay = b"\x00" * (300 * 1024)
        data = pe_data + overlay
        verdict = detect_exe_subtype_full(data)
        assert verdict.chosen is not None
        assert verdict.chosen.family == "nsis"
        assert any(e.strength == "structural" for e in verdict.chosen.evidence)
