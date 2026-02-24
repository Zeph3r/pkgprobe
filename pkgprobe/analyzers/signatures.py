from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class SignatureHit:
    name: str
    confidence: float
    evidence: str


def _extract_strings(data: bytes, min_len: int = 6, max_count: int = 4000) -> List[str]:
    """
    Extract a limited set of ASCII and UTF-16LE-ish strings from bytes.
    Not perfect—good enough for MVP heuristics.
    """
    out: List[str] = []

    # ASCII strings
    cur = bytearray()
    for b in data:
        if 32 <= b <= 126:
            cur.append(b)
            if len(cur) >= 256:
                # cap long runs
                out.append(cur.decode("ascii", errors="ignore"))
                cur.clear()
                if len(out) >= max_count:
                    return out
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
                if len(out) >= max_count:
                    return out
            cur.clear()

    if len(cur) >= min_len and len(out) < max_count:
        out.append(cur.decode("ascii", errors="ignore"))

    # UTF-16LE-ish: look for alternating printable/0x00
    out2: List[str] = []
    cur_u16 = bytearray()
    i = 0
    n = len(data)
    while i + 1 < n:
        ch = data[i]
        zero = data[i + 1]
        if zero == 0x00 and 32 <= ch <= 126:
            cur_u16.extend([ch])
            if len(cur_u16) >= 256:
                out2.append(cur_u16.decode("ascii", errors="ignore"))
                cur_u16.clear()
                if len(out) + len(out2) >= max_count:
                    break
        else:
            if len(cur_u16) >= min_len:
                out2.append(cur_u16.decode("ascii", errors="ignore"))
                if len(out) + len(out2) >= max_count:
                    break
            cur_u16.clear()
        i += 2

    if len(cur_u16) >= min_len and (len(out) + len(out2)) < max_count:
        out2.append(cur_u16.decode("ascii", errors="ignore"))

    return out + out2


def detect_installer_type(exe_bytes: bytes) -> Tuple[str, float, List[SignatureHit]]:
    strings = _extract_strings(exe_bytes)
    s_join = "\n".join(strings).lower()

    hits: List[SignatureHit] = []

    # Inno Setup
    if "inno setup" in s_join or "innosetup" in s_join or "unins000.exe" in s_join:
        hits.append(SignatureHit("Inno Setup", 0.92, "Matched 'Inno Setup' / 'unins000.exe' strings"))

    # NSIS
    if "nsis" in s_join or "nullsoft" in s_join or "nsis error" in s_join:
        hits.append(SignatureHit("NSIS", 0.90, "Matched NSIS/Nullsoft strings"))

    # InstallShield
    if "installshield" in s_join or "isscript" in s_join or "setup.inx" in s_join:
        hits.append(SignatureHit("InstallShield", 0.82, "Matched InstallShield strings"))

    # WiX Burn
    if "burn" in s_join and ("wix" in s_join or "bundle" in s_join or "bootstrapper" in s_join):
        hits.append(SignatureHit("WiX Burn / Bootstrapper", 0.80, "Matched Burn/WiX bundle strings"))

    # Squirrel
    if "squirrel" in s_join or "update.exe" in s_join:
        hits.append(SignatureHit("Squirrel", 0.70, "Matched Squirrel 'Update.exe' strings"))

    # MSIX/AppX hints
    if ".appx" in s_join or ".msix" in s_join or "appxmanifest.xml" in s_join:
        hits.append(SignatureHit("MSIX/AppX (hint)", 0.55, "Matched MSIX/AppX related strings"))

    if not hits:
        return ("Unknown EXE installer", 0.20, [])

    # Pick best hit
    best = max(hits, key=lambda h: h.confidence)
    return (best.name, best.confidence, hits)
