"""
Intune Win32 packaging from verified trace output.

This wraps Microsoft's IntuneWinAppUtil.exe (external tool) to produce a
`.intunewin` artifact from:
- the original installer (payload)
- a generated install script (uses verified silent args)
- a generated detection script (uses best detection candidate)

Design goals:
- Deterministic, job-directory based IO (easy to run in local or cloud worker)
- No reliance on global state besides the external packaging tool path
"""

from __future__ import annotations

import glob
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .verified_manifest import DetectionCandidate, VerifiedTraceManifest


class IntuneWinPackagerError(RuntimeError):
    pass


@dataclass(frozen=True)
class IntuneWinPackagerConfig:
    intunewin_util_path: str = "IntuneWinAppUtil.exe"
    overwrite: bool = False
    timeout_sec: int = 60 * 10
    allow_unverified: bool = False


class IntuneWinPackager:
    def __init__(self, config: IntuneWinPackagerConfig) -> None:
        self._config = config

    def pack_from_trace_output(
        self,
        *,
        trace_output_dir: Path,
        output_dir: Path,
        installer_path: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
    ) -> Path:
        trace_output_dir = Path(trace_output_dir)
        output_dir = Path(output_dir)
        if not trace_output_dir.is_dir():
            raise IntuneWinPackagerError(f"trace_output_dir not found: {trace_output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        if manifest_path is None:
            manifest_path = trace_output_dir / "verified_manifest.json"
        if not manifest_path.is_file():
            raise IntuneWinPackagerError(f"manifest not found: {manifest_path}")

        manifest = VerifiedTraceManifest.from_json(manifest_path.read_text(encoding="utf-8"))
        if not manifest.verified and not self._config.allow_unverified:
            msg = "Manifest is not verified; refusing to package."
            if manifest.verification_errors:
                msg += " " + "; ".join(manifest.verification_errors)
            raise IntuneWinPackagerError(msg)

        if installer_path is None:
            # Pick first plausible installer in the trace output directory.
            candidates = []
            candidates.extend(sorted(trace_output_dir.glob("*.exe")))
            candidates.extend(sorted(trace_output_dir.glob("*.msi")))
            if not candidates:
                raise IntuneWinPackagerError("No installer found in trace_output_dir; pass --installer explicitly")
            installer_path = candidates[0]
        installer_path = Path(installer_path)
        if not installer_path.is_file():
            raise IntuneWinPackagerError(f"installer not found: {installer_path}")

        staging_dir = output_dir / "intunewin_staging"
        if staging_dir.exists() and not self._config.overwrite:
            raise IntuneWinPackagerError(f"staging_dir exists (use --overwrite): {staging_dir}")
        staging_dir.mkdir(parents=True, exist_ok=True)

        # Copy payload into staging
        staged_installer = staging_dir / installer_path.name
        staged_installer.write_bytes(installer_path.read_bytes())

        install_ps1 = staging_dir / "install.ps1"
        detect_ps1 = staging_dir / "detect.ps1"
        install_ps1.write_text(self._render_install_ps1(staged_installer.name, manifest.silent_args), encoding="utf-8")
        detect_ps1.write_text(self._render_detect_ps1(manifest.detection_candidates), encoding="utf-8")

        # IntuneWinAppUtil creates a file named <setupfile>.intunewin in output dir.
        produced = output_dir / f"{staged_installer.name}.intunewin"
        if produced.exists() and not self._config.overwrite:
            raise IntuneWinPackagerError(f"Output exists (use --overwrite): {produced}")

        self._run_intunewin_util(
            source_dir=staging_dir,
            setup_file=staged_installer.name,
            output_dir=output_dir,
        )

        if not produced.is_file():
            # Fallback: try to locate any *.intunewin produced.
            matches = list(output_dir.glob("*.intunewin"))
            if len(matches) == 1:
                return matches[0]
            raise IntuneWinPackagerError(f"Expected .intunewin not found at: {produced}")

        return produced

    def _run_intunewin_util(self, *, source_dir: Path, setup_file: str, output_dir: Path) -> None:
        args = [
            self._config.intunewin_util_path,
            "-c",
            str(source_dir),
            "-s",
            setup_file,
            "-o",
            str(output_dir),
            "-q",
        ]

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=self._config.timeout_sec,
            check=False,
            creationflags=creationflags,
        )
        if proc.returncode != 0:
            raise IntuneWinPackagerError(
                f"IntuneWinAppUtil failed (code={proc.returncode}) "
                f"(stdout={proc.stdout!r}, stderr={proc.stderr!r})"
            )

    @staticmethod
    def _render_install_ps1(installer_filename: str, silent_args: list[str]) -> str:
        # Use Start-Process -Wait for deterministic completion.
        args = " ".join([f'"{a}"' if " " in a else a for a in (silent_args or [])])
        return (
            "$ErrorActionPreference = 'Stop'\n"
            "$here = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
            f"$installer = Join-Path $here '{installer_filename}'\n"
            f"$args = @({', '.join([repr(a) for a in (silent_args or [])])})\n"
            "Write-Host \"Running installer: $installer\"\n"
            "if ($args.Count -gt 0) {\n"
            "  $p = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru\n"
            "} else {\n"
            "  $p = Start-Process -FilePath $installer -Wait -PassThru\n"
            "}\n"
            "exit $p.ExitCode\n"
        )

    @staticmethod
    def _render_detect_ps1(candidates: list[DetectionCandidate]) -> str:
        # Intune detection scripts signal "installed" by exiting 0.
        # We choose the highest confidence candidate.
        best = None
        for c in candidates:
            if best is None or float(c.confidence) > float(best.confidence):
                best = c

        if best is None:
            return "exit 1\n"

        if best.type == "registry_key":
            # ProcMon exports registry keys in a variety of formats; normalize for PowerShell.
            path = best.value
            # Convert common prefixes
            path = path.replace("HKLM\\", "HKLM:\\").replace("HKCU\\", "HKCU:\\")
            return (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"if (Test-Path \"{path}\") {{ exit 0 }}\n"
                "exit 1\n"
            )
        if best.type == "file_exists":
            return (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"if (Test-Path \"{best.value}\") {{ exit 0 }}\n"
                "exit 1\n"
            )
        if best.type == "service_exists":
            return (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"$s = Get-Service -Name \"{best.value}\" -ErrorAction SilentlyContinue\n"
                "if ($null -ne $s) { exit 0 }\n"
                "exit 1\n"
            )
        if best.type == "scheduled_task_exists":
            return (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"$t = Get-ScheduledTask -TaskName \"{best.value}\" -ErrorAction SilentlyContinue\n"
                "if ($null -ne $t) { exit 0 }\n"
                "exit 1\n"
            )

        return "exit 1\n"

