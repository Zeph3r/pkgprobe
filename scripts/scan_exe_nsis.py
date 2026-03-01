#!/usr/bin/env python
"""
Scan an EXE for NSIS-related markers (for debugging subtype detection).
Usage: uv run python scripts/scan_exe_nsis.py <path-to-exe>
"""
from __future__ import annotations

import sys
from pathlib import Path


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        out.append(i)
        start = i + 1
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/scan_exe_nsis.py <path-to-exe>", file=sys.stderr)
        return 1
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        return 1
    data = path.read_bytes()
    n = len(data)
    print(f"File: {path}")
    print(f"Size: {n} bytes")
    print(f"MZ header: {data[:2] == b'MZ'}")
    sig_le = b"\xef\xbe\xad\xde"
    sig_be = b"\xde\xad\xbe\xef"
    for name, needle in [
        ("0xDEADBEEF (LE)", sig_le),
        ("0xDEADBEEF (BE)", sig_be),
        ("NullsoftInst", b"NullsoftInst"),
        ("nullsoft", b"nullsoft"),
        ("NSIS Error", b"NSIS Error"),
        ("__NSIS", b"__NSIS"),
        ("7-Zip (product)", b"7-Zip"),
        ("7-zip (product)", b"7-zip"),
    ]:
        offsets = find_all(data, needle)
        if offsets:
            print(f"  {name}: found at {len(offsets)} place(s), first at offset(s) {offsets[:5]}{'...' if len(offsets) > 5 else ''}")
        else:
            print(f"  {name}: not found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
