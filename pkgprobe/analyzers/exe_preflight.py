"""
Aggressive EXE preflight: help-screen probe, optional 7-Zip listing, nested artifact hints.

Read-only / inspect-only — does not run nested installers. Best-effort on non-Windows.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Cap captured help output to avoid huge memory use
_HELP_MAX_BYTES = 256_000
_7Z_LIST_TIMEOUT_SEC = 25
_HELP_TIMEOUT_SEC = 8


@dataclass
class ExePreflightResult:
    """Structured preflight output stored under InstallPlan.metadata[\"preflight\"]."""

    help_attempted: bool = False
    help_succeeded: bool = False
    help_snippet: str = ""
    help_error: str = ""
    seven_zip_path: str | None = None
    seven_zip_listing: list[str] = field(default_factory=list)
    seven_zip_error: str = ""
    nested_msi_names: list[str] = field(default_factory=list)
    setup_ini_suspected: bool = False
    squirrel_suspected: bool = False
    burn_wix_suspected: bool = False
    notes: list[str] = field(default_factory=list)

    def to_json_dict(self) -> dict[str, Any]:
        return {
            "help_attempted": self.help_attempted,
            "help_succeeded": self.help_succeeded,
            "help_snippet": self.help_snippet[:8000],
            "help_error": self.help_error,
            "seven_zip_path": self.seven_zip_path,
            "seven_zip_listing_count": len(self.seven_zip_listing),
            "seven_zip_sample": self.seven_zip_listing[:50],
            "seven_zip_error": self.seven_zip_error,
            "nested_msi_names": self.nested_msi_names,
            "setup_ini_suspected": self.setup_ini_suspected,
            "squirrel_suspected": self.squirrel_suspected,
            "burn_wix_suspected": self.burn_wix_suspected,
            "notes": self.notes,
        }


def find_7z_executable() -> Path | None:
    """Return path to 7z.exe if on PATH or common install locations."""
    for name in ("7z", "7z.exe"):
        p = shutil.which(name)
        if p:
            return Path(p)
    if os.name == "nt":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pfx86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        for base in (pf, pfx86):
            if not base:
                continue
            cand = Path(base) / "7-Zip" / "7z.exe"
            if cand.is_file():
                return cand
    return None


def _truncate(s: str, max_bytes: int) -> str:
    raw = s.encode("utf-8", errors="replace")
    if len(raw) <= max_bytes:
        return s
    return raw[:max_bytes].decode("utf-8", errors="replace") + "…"


def run_help_probe(exe_path: Path) -> tuple[bool, str, str]:
    """
    Run `exe /?` then `exe /help` if first fails. Windows-focused.
    Returns (succeeded, combined_snippet, error_message).
    """
    if not exe_path.is_file():
        return False, "", "file not found"
    if os.name != "nt":
        return False, "", "help probe skipped (non-Windows)"

    chunks: list[str] = []
    err: list[str] = []
    for args in (["/?"], ["/help"]):
        try:
            proc = subprocess.run(
                [str(exe_path), *args],
                capture_output=True,
                timeout=_HELP_TIMEOUT_SEC,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,  # type: ignore[attr-defined]
            )
            out = (proc.stdout or b"") + (proc.stderr or b"")
            text = out.decode("utf-8", errors="replace")
            if text.strip():
                chunks.append(f"--- args {args} ---\n{_truncate(text, _HELP_MAX_BYTES // 2)}")
        except subprocess.TimeoutExpired:
            err.append(f"timeout:{args}")
        except OSError as e:
            err.append(f"{args}:{e!s}")

    combined = "\n".join(chunks)
    if combined.strip():
        return True, _truncate(combined, _HELP_MAX_BYTES), "" if not err else "; ".join(err)
    return False, "", "; ".join(err) if err else "no output"


def _parse_7z_list_output(stdout: str) -> list[str]:
    """Extract path-like tokens from `7z l` output."""
    found: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"[^\s<>\"|]+\.(?:msi|exe|ini|cfg|dat)\b", stdout, re.IGNORECASE):
        s = m.group(0).strip()
        if s and s not in seen:
            seen.add(s)
            found.append(s)
    for line in stdout.splitlines():
        low = line.lower()
        if "setup.ini" in low or "squirrel" in low or ".wixburn" in low:
            t = line.strip()[:300]
            if t and t not in seen:
                seen.add(t)
                found.append(t)
    return found


def list_with_7z(exe_path: Path, seven_zip: Path) -> tuple[list[str], str]:
    """Run `7z l` on the file; return (names, error)."""
    try:
        proc = subprocess.run(
            [str(seven_zip), "l", str(exe_path)],
            capture_output=True,
            text=True,
            timeout=_7Z_LIST_TIMEOUT_SEC,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,  # type: ignore[attr-defined]
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if not out.strip():
            return [], f"7z exit {proc.returncode}"
        listing = _parse_7z_list_output(out)
        return listing, "" if proc.returncode == 0 else f"7z exit {proc.returncode}"
    except subprocess.TimeoutExpired:
        return [], "7z timeout"
    except OSError as e:
        return [], str(e)


def _scan_listing_for_hints(names: list[str]) -> tuple[list[str], bool, bool, bool]:
    nested_msi: list[str] = []
    setup_ini = False
    squirrel = False
    burn = False
    joined = "\n".join(names).lower()
    for n in names:
        low = n.lower()
        if low.endswith(".msi"):
            nested_msi.append(n)
        if "setup.ini" in low or low.endswith("setup.ini"):
            setup_ini = True
        if "squirrel" in low or re.search(r"app-[^\\/]+\.exe", low):
            squirrel = True
        if ".wixburn" in low or "wix" in joined:
            burn = True
    return nested_msi, setup_ini, squirrel, burn


def run_exe_preflight(exe_path: str) -> ExePreflightResult:
    """Run full preflight for an EXE path; safe to call on any OS."""
    path = Path(exe_path)
    res = ExePreflightResult()

    ok, snippet, herr = run_help_probe(path)
    res.help_attempted = os.name == "nt"
    res.help_succeeded = ok
    res.help_snippet = snippet
    res.help_error = herr

    if not ok and os.name == "nt":
        res.notes.append("Help probe produced no output (GUI-only or unsupported /? ).")

    seven = find_7z_executable()
    if seven is None:
        res.seven_zip_error = "7-Zip CLI not found (install 7-Zip or add 7z.exe to PATH for deeper inspection)."
        res.notes.append(res.seven_zip_error)
        return res

    res.seven_zip_path = str(seven)
    listing, zerr = list_with_7z(path, seven)
    res.seven_zip_listing = listing
    res.seven_zip_error = zerr

    nested, setup_ini, squirrel, burn = _scan_listing_for_hints(listing)
    res.nested_msi_names = nested
    res.setup_ini_suspected = setup_ini
    res.squirrel_suspected = squirrel
    res.burn_wix_suspected = burn

    if nested:
        res.notes.append(f"Nested MSI-like entries in archive listing: {nested[:5]}")
    if setup_ini:
        res.notes.append("setup.ini-like file seen in listing (InstallShield-style hint).")
    if squirrel:
        res.notes.append("Squirrel-like paths (app-*.exe) suggested in listing.")
    if burn:
        res.notes.append("WiX Burn / bundle hints in listing.")

    return res


def assess_silent_viability_and_recommendation(
    *,
    installer_type: str,
    confidence: float,
    preflight: ExePreflightResult | None,
) -> tuple[str, str]:
    """
    Return (silent_viability, recommendation) for InstallPlan fields.
    Values: silent_viability in unknown|likely|unlikely; recommendation in silent_may_work|trace_recommended.
    """
    it = installer_type.lower()

    if "inno" in it or "nsis" in it:
        if confidence >= 0.75:
            return "likely", "silent_may_work"
        return "unknown", "silent_may_work"

    if "installshield" in it or "burn" in it or "wix" in it:
        return "unknown", "silent_may_work"

    if "squirrel" in it:
        return "unlikely", "trace_recommended"

    if "msix" in it or "appx" in it:
        return "unlikely", "trace_recommended"

    if preflight:
        if preflight.nested_msi_names:
            return "unknown", "trace_recommended"
        if preflight.squirrel_suspected:
            return "unlikely", "trace_recommended"
        if preflight.setup_ini_suspected:
            return "unknown", "trace_recommended"
        if preflight.help_succeeded and len(preflight.help_snippet) > 80:
            if confidence >= 0.5:
                return "unknown", "silent_may_work"
        if not preflight.help_succeeded and confidence < 0.45:
            return "unlikely", "trace_recommended"

    if confidence >= 0.75:
        return "unknown", "silent_may_work"

    if confidence < 0.45:
        return "unlikely", "trace_recommended"

    return "unknown", "silent_may_work"


def assess_deployment(
    *,
    installer_type: str,
    confidence: float,
    preflight: ExePreflightResult | None,
    confidence_tier: str = "low",
) -> dict[str, Any]:
    """
    Build a DeploymentAssessment dict (matches pkgprobe.models.DeploymentAssessment).

    Separates operational viability from family identification: same family
    can map to different risk levels depending on confidence and preflight.
    """
    sv, rec = assess_silent_viability_and_recommendation(
        installer_type=installer_type,
        confidence=confidence,
        preflight=preflight,
    )

    it = installer_type.lower()
    risk_factors: list[str] = []

    if "inno" in it or "nsis" in it:
        if confidence_tier == "high":
            risk = "low"
            next_step = "auto_package"
            tier = "simple"
            tier_reason = "Well-known silent switches; high detection confidence"
        else:
            risk = "moderate"
            next_step = "trace_recommended" if rec == "trace_recommended" else "auto_package"
            tier = "pro"
            tier_reason = "Medium confidence; may need trace to confirm silent behavior"

    elif "installshield" in it:
        risk = "moderate"
        next_step = "trace_recommended"
        tier = "pro"
        tier_reason = "InstallShield often needs syntax trial; trace recommended"
        risk_factors.append("InstallShield often requires /s /v\"/qn\" syntax variations")

    elif "burn" in it or "bootstrapper" in it or "wix" in it:
        risk = "high"
        next_step = "trace_recommended"
        tier = "auto_wrap"
        tier_reason = "Burn bundles chain payloads; high failure rate without trace"
        risk_factors.extend([
            "Burn bundles may chain multiple MSI/EXE payloads",
            "Prerequisite installers may behave independently",
            "/quiet may not suppress all chained UI",
            "Confidence capped until validated by trace",
        ])

    elif "squirrel" in it:
        risk = "high"
        next_step = "trace_recommended"
        tier = "auto_wrap"
        tier_reason = "Per-user installer with non-standard lifecycle; trace or wrap required"
        risk_factors.extend([
            "Per-user install to %LOCALAPPDATA%",
            "Update.exe dependency for lifecycle management",
            "Non-standard uninstall behavior",
        ])

    elif "msix" in it or "appx" in it:
        risk = "moderate"
        next_step = "alternate_deployment_path"
        tier = "pro"
        tier_reason = "MSIX/AppX wrapper; consider native MSIX deployment path"
        risk_factors.append("Consider native MSIX deployment via Add-AppxPackage")
        if confidence >= 0.75:
            risk_factors.append(
                "Strong MSIX/AppX evidence; EXE wrapper may not be ideal "
                "for traditional Win32 packaging"
            )

    else:
        risk = "high"
        next_step = "manual_review"
        tier = "auto_wrap"
        tier_reason = "Unknown installer family; automated packaging unlikely to succeed"
        risk_factors.append("Unknown installer family; cannot assess deployment risk")
        if preflight and preflight.nested_msi_names:
            risk_factors.append("Nested MSI payloads detected; manual inspection needed")

    result = {
        "silent_viability": sv,
        "deployment_risk": risk,
        "recommended_next_step": next_step,
        "packaging_tier": tier,
        "tier_reason": tier_reason,
        "risk_factors": risk_factors,
    }

    from pkgprobe.analyzers.telemetry import get_telemetry
    tel = get_telemetry()
    if tel.enabled:
        tel.record(
            "deployment_assessed",
            installer_type=installer_type,
            confidence=confidence,
            confidence_tier=confidence_tier,
            deployment_risk=risk,
            recommended_next_step=next_step,
            risk_factor_count=len(risk_factors),
            preflight_promotion=bool(
                preflight and (preflight.burn_wix_suspected or preflight.squirrel_suspected)
            ),
        )

    return result
