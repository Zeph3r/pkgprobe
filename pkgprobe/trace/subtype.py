"""
EXE sub-type detection with signal score.

Combines (1) case-insensitive string markers (ASCII + UTF-16LE) and (2) structural
PE overlay heuristics. NSIS packs script into a single EXE with payload appended
after the PE; literal markers may be missing when compression is used, so
structural features (small stub + large overlay) are strong generic signals.

Family remains msi | exe; subtype identifies the installer framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pkgprobe.trace.evidence import (
    READ_FULL_MAX_SIZE,
    READ_HEAD_SIZE,
    READ_TAIL_SIZE,
    read_head,
    read_tail,
)

ExeSubtype = Literal["nsis", "inno", "installshield", "burn", "squirrel", "msix_wrapper"]


@dataclass(frozen=True)
class FamilyEvidence:
    marker: str
    strength: Literal["strong", "weak", "structural"]


@dataclass(frozen=True)
class FamilyCandidate:
    family: ExeSubtype
    confidence: float
    evidence: list[FamilyEvidence]
    rejected: bool = False
    rejection_reason: str | None = None


@dataclass(frozen=True)
class FamilyVerdict:
    chosen: FamilyCandidate | None
    alternatives: list[FamilyCandidate]
    confidence_tier: Literal["high", "medium", "low"]


def _confidence_tier(confidence: float) -> Literal["high", "medium", "low"]:
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"


# Confidence levels (deterministic)
_CONF_STRONG_MATCH = 0.75  # one strong textual NSIS marker
_CONF_MULTIPLE_MATCH = 0.85  # two+ strong textual markers
_CONF_WEAK_ONLY = 0.6  # weak textual marker only
_CONF_STRUCTURAL = 0.65  # structural overlay heuristic alone (no product-specific)
_CONF_COMBINED = 0.80  # textual + structural both present
_CONF_NO_MARKERS = 0.3

# Burn-specific confidence caps (lower than generic to reflect chaining risk)
_CONF_BURN_STRONG = 0.70
_CONF_BURN_MULTIPLE = 0.80

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

# WiX Burn / bootstrapper bundles
_BURN_STRONG: tuple[bytes, ...] = (
    b".wixburn",
    b"wixbundlemanifest",
    b"bootstrapperapplication",
    b"bootstrappercore.dll",
    b"wixstdba",
)
_BURN_WEAK = b"wix"

# Squirrel (Electron / .NET app distribution)
_SQUIRREL_STRONG: tuple[bytes, ...] = (
    b"squirreltemp",
    b"squirrel.windows",
    b"squirrel-install",
)
_SQUIRREL_WEAK = b"squirrel"

# MSIX / AppX wrapper EXEs
_MSIX_MARKERS: tuple[bytes, ...] = (
    b"appxmanifest.xml",
    b"appxblockmap.xml",
    b"appxbundlemanifest.xml",
    b"add-appxpackage",
)


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


def _count_markers(
    markers: tuple[bytes, ...], data_lower: bytes, data_raw: bytes,
) -> int:
    return sum(1 for p in markers if _pattern_in_data(p, data_lower, data_raw))


def _matched_markers(
    markers: tuple[bytes, ...], data_lower: bytes, data_raw: bytes,
) -> list[str]:
    return [p.decode("ascii") for p in markers if _pattern_in_data(p, data_lower, data_raw)]


def _detect_exe_subtype_from_bytes(data: bytes) -> tuple[ExeSubtype | None, float]:
    """
    Detect EXE sub-type from a byte buffer. MZ is not required here (caller checks).

    Priority: Inno > InstallShield > Burn > Squirrel > MSIX > NSIS.
    NSIS is checked last because its structural heuristic (small PE stub + large
    overlay) is the broadest and most likely to false-positive over specific families.
    """
    if len(data) < 2:
        return None, _CONF_NO_MARKERS

    # NSIS format signature in overlay — strongest NSIS-specific signal.
    # Checked early but only returned after ruling out higher-priority families.
    nsis_magic = _NSIS_MAGIC_SIG_LE in data or _NSIS_MAGIC_SIG_BE in data

    data_lower = _to_lower_ascii(data)

    # --- gather evidence for every family ---
    inno_count = _count_markers(_INNO_MARKERS, data_lower, data)
    ishield_count = _count_markers(_INSTALLSHIELD_MARKERS, data_lower, data)

    burn_strong_count = _count_markers(_BURN_STRONG, data_lower, data)
    burn_weak_found = _pattern_in_data(_BURN_WEAK, data_lower, data)

    squirrel_strong_count = _count_markers(_SQUIRREL_STRONG, data_lower, data)
    squirrel_weak_found = _pattern_in_data(_SQUIRREL_WEAK, data_lower, data)

    msix_count = _count_markers(_MSIX_MARKERS, data_lower, data)

    nsis_strong_found: set[bytes] = set()
    for pat in _NSIS_STRONG:
        if _pattern_in_data(pat, data_lower, data):
            nsis_strong_found.add(pat)
    nsis_weak_found = _pattern_in_data(_NSIS_WEAK, data_lower, data)

    nsis_structural = _has_nsis_structural_evidence(data)

    # --- priority resolution ---

    if inno_count > 0:
        return "inno", _CONF_MULTIPLE_MATCH if inno_count > 1 else _CONF_STRONG_MATCH

    if ishield_count > 0:
        return "installshield", _CONF_MULTIPLE_MATCH if ishield_count > 1 else _CONF_STRONG_MATCH

    if burn_strong_count > 0:
        return "burn", _CONF_MULTIPLE_MATCH if burn_strong_count >= 2 else _CONF_STRONG_MATCH
    if burn_weak_found and not nsis_strong_found and not nsis_magic:
        return "burn", _CONF_WEAK_ONLY

    if squirrel_strong_count > 0:
        return "squirrel", _CONF_MULTIPLE_MATCH if squirrel_strong_count >= 2 else _CONF_STRONG_MATCH
    if squirrel_weak_found and not nsis_strong_found and not nsis_magic:
        return "squirrel", _CONF_WEAK_ONLY

    if msix_count > 0:
        return "msix_wrapper", _CONF_MULTIPLE_MATCH if msix_count >= 2 else _CONF_STRONG_MATCH

    # NSIS: magic first, then combine textual + structural evidence.
    if nsis_magic:
        return "nsis", _CONF_MULTIPLE_MATCH

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


def _detect_exe_subtype_full_from_bytes(data: bytes) -> FamilyVerdict:
    """
    Full detection with evidence trail and rejected-family reasoning.
    Accumulates FamilyCandidate for every family with evidence, picks winner
    by priority, and marks losers with rejection reasons.

    Priority: Inno > InstallShield > Burn > Squirrel > MSIX > NSIS.
    Burn confidence is capped below other families to reflect chaining risk.
    """
    if len(data) < 2:
        return FamilyVerdict(chosen=None, alternatives=[], confidence_tier="low")

    nsis_magic = _NSIS_MAGIC_SIG_LE in data or _NSIS_MAGIC_SIG_BE in data
    data_lower = _to_lower_ascii(data)

    # Pre-compute NSIS strong presence for Burn/Squirrel weak-marker guards
    has_nsis_strong = any(
        _pattern_in_data(p, data_lower, data) for p in _NSIS_STRONG
    )

    all_candidates: list[FamilyCandidate] = []

    # --- Inno ---
    inno_hits = _matched_markers(_INNO_MARKERS, data_lower, data)
    if inno_hits:
        conf = _CONF_MULTIPLE_MATCH if len(inno_hits) > 1 else _CONF_STRONG_MATCH
        all_candidates.append(FamilyCandidate(
            family="inno", confidence=conf,
            evidence=[FamilyEvidence(m, "strong") for m in inno_hits],
        ))

    # --- InstallShield ---
    ishield_hits = _matched_markers(_INSTALLSHIELD_MARKERS, data_lower, data)
    if ishield_hits:
        conf = _CONF_MULTIPLE_MATCH if len(ishield_hits) > 1 else _CONF_STRONG_MATCH
        all_candidates.append(FamilyCandidate(
            family="installshield", confidence=conf,
            evidence=[FamilyEvidence(m, "strong") for m in ishield_hits],
        ))

    # --- Burn (confidence capped) ---
    burn_strong_hits = _matched_markers(_BURN_STRONG, data_lower, data)
    burn_weak = _pattern_in_data(_BURN_WEAK, data_lower, data)

    if burn_strong_hits:
        conf = _CONF_BURN_MULTIPLE if len(burn_strong_hits) >= 2 else _CONF_BURN_STRONG
        all_candidates.append(FamilyCandidate(
            family="burn", confidence=conf,
            evidence=[FamilyEvidence(m, "strong") for m in burn_strong_hits],
        ))
    elif burn_weak:
        if not has_nsis_strong and not nsis_magic:
            all_candidates.append(FamilyCandidate(
                family="burn", confidence=_CONF_WEAK_ONLY,
                evidence=[FamilyEvidence("wix", "weak")],
            ))
        else:
            all_candidates.append(FamilyCandidate(
                family="burn", confidence=_CONF_WEAK_ONLY,
                evidence=[FamilyEvidence("wix", "weak")],
                rejected=True,
                rejection_reason="weak 'wix' marker overridden by NSIS strong evidence",
            ))

    # --- Squirrel ---
    sq_strong_hits = _matched_markers(_SQUIRREL_STRONG, data_lower, data)
    sq_weak = _pattern_in_data(_SQUIRREL_WEAK, data_lower, data)

    if sq_strong_hits:
        conf = _CONF_MULTIPLE_MATCH if len(sq_strong_hits) >= 2 else _CONF_STRONG_MATCH
        all_candidates.append(FamilyCandidate(
            family="squirrel", confidence=conf,
            evidence=[FamilyEvidence(m, "strong") for m in sq_strong_hits],
        ))
    elif sq_weak:
        if not has_nsis_strong and not nsis_magic:
            all_candidates.append(FamilyCandidate(
                family="squirrel", confidence=_CONF_WEAK_ONLY,
                evidence=[FamilyEvidence("squirrel", "weak")],
            ))
        else:
            all_candidates.append(FamilyCandidate(
                family="squirrel", confidence=_CONF_WEAK_ONLY,
                evidence=[FamilyEvidence("squirrel", "weak")],
                rejected=True,
                rejection_reason="weak 'squirrel' marker overridden by NSIS strong evidence",
            ))

    # --- MSIX ---
    msix_hits = _matched_markers(_MSIX_MARKERS, data_lower, data)
    if msix_hits:
        conf = _CONF_MULTIPLE_MATCH if len(msix_hits) >= 2 else _CONF_STRONG_MATCH
        all_candidates.append(FamilyCandidate(
            family="msix_wrapper", confidence=conf,
            evidence=[FamilyEvidence(m, "strong") for m in msix_hits],
        ))

    # --- NSIS ---
    nsis_strong_matched = _matched_markers(_NSIS_STRONG, data_lower, data)
    nsis_weak = _pattern_in_data(_NSIS_WEAK, data_lower, data)
    nsis_structural = _has_nsis_structural_evidence(data)

    nsis_ev: list[FamilyEvidence] = []
    if nsis_magic:
        nsis_ev.append(FamilyEvidence("nsis_magic_0xDEADBEEF", "strong"))
    for m in nsis_strong_matched:
        nsis_ev.append(FamilyEvidence(m, "strong"))
    if nsis_weak and not nsis_strong_matched and not nsis_magic:
        nsis_ev.append(FamilyEvidence("nsis", "weak"))
    if nsis_structural:
        nsis_ev.append(FamilyEvidence("nsis_structural_overlay", "structural"))

    if nsis_ev:
        if nsis_magic:
            nsis_conf = _CONF_MULTIPLE_MATCH
        elif nsis_strong_matched:
            text_conf = (
                _CONF_MULTIPLE_MATCH if len(nsis_strong_matched) >= 2
                else _CONF_STRONG_MATCH
            )
            nsis_conf = max(text_conf, _CONF_COMBINED) if nsis_structural else text_conf
        elif nsis_weak:
            nsis_conf = (
                max(_CONF_WEAK_ONLY, _CONF_COMBINED) if nsis_structural
                else _CONF_WEAK_ONLY
            )
        else:
            nsis_conf = _CONF_STRUCTURAL
        all_candidates.append(FamilyCandidate(
            family="nsis", confidence=nsis_conf, evidence=nsis_ev,
        ))

    # --- Priority resolution ---
    priority_order: list[ExeSubtype] = [
        "inno", "installshield", "burn", "squirrel", "msix_wrapper", "nsis",
    ]

    eligible = [c for c in all_candidates if not c.rejected]
    pre_rejected = [c for c in all_candidates if c.rejected]

    chosen: FamilyCandidate | None = None
    alternatives: list[FamilyCandidate] = list(pre_rejected)

    for family in priority_order:
        match = next((c for c in eligible if c.family == family), None)
        if match is None:
            continue
        if chosen is None:
            chosen = match
        else:
            alternatives.append(FamilyCandidate(
                family=match.family,
                confidence=match.confidence,
                evidence=match.evidence,
                rejected=True,
                rejection_reason=(
                    f"outprioritized by {chosen.family}: "
                    "higher-priority evidence present"
                ),
            ))

    alternatives.sort(key=lambda c: c.confidence, reverse=True)
    conf = chosen.confidence if chosen else _CONF_NO_MARKERS
    return FamilyVerdict(
        chosen=chosen, alternatives=alternatives,
        confidence_tier=_confidence_tier(conf),
    )


def detect_exe_subtype_full(data: bytes) -> FamilyVerdict:
    """
    Full detection with evidence trail and alternatives.
    Returns FamilyVerdict with chosen family, rejected alternatives, and
    confidence tier for downstream gating.
    Returns empty verdict (chosen=None, tier="low") if data missing MZ.
    """
    if len(data) < 2 or data[:2] != b"MZ":
        return FamilyVerdict(chosen=None, alternatives=[], confidence_tier="low")
    verdict = _detect_exe_subtype_full_from_bytes(data)

    from pkgprobe.analyzers.telemetry import get_telemetry
    tel = get_telemetry()
    if tel.enabled:
        tel.record(
            "family_detected",
            chosen_family=verdict.chosen.family if verdict.chosen else None,
            chosen_confidence=verdict.chosen.confidence if verdict.chosen else None,
            confidence_tier=verdict.confidence_tier,
            alternatives=[
                {"family": a.family, "confidence": a.confidence, "reason": a.rejection_reason}
                for a in verdict.alternatives
            ],
            strong_evidence_count=sum(
                1 for e in (verdict.chosen.evidence if verdict.chosen else [])
                if e.strength == "strong"
            ),
            weak_evidence_count=sum(
                1 for e in (verdict.chosen.evidence if verdict.chosen else [])
                if e.strength == "weak"
            ),
        )

    return verdict


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
