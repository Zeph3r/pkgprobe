"""
Generate a PSADT (PowerShell App Deployment Toolkit) wrapper directory
for GUI-only installers that lack viable silent switches.

The wrapper is structured so IntuneWinAppUtil can package it directly,
with Deploy-Application.ps1 as the setup file.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .verified_manifest import DetectionCandidate

logger = logging.getLogger(__name__)

_BUNDLED_TEMPLATE_DIR = Path(__file__).resolve().parent / "psadt_template"


@dataclass(frozen=True)
class PsadtWrapperConfig:
    psadt_toolkit_path: str | None = None
    serviceui_path: str | None = None
    show_progress: bool = True
    allow_reboot_passthrough: bool = False


class PsadtWrapperError(RuntimeError):
    pass


class PsadtWrapperGenerator:
    def __init__(self, config: PsadtWrapperConfig | None = None) -> None:
        self._config = config or PsadtWrapperConfig()

    def _resolve_toolkit_dir(self) -> Path:
        if self._config.psadt_toolkit_path:
            p = Path(self._config.psadt_toolkit_path)
            if not p.is_dir():
                raise PsadtWrapperError(
                    f"Custom PSADT toolkit path not found: {p}"
                )
            return p
        if not _BUNDLED_TEMPLATE_DIR.is_dir():
            raise PsadtWrapperError(
                f"Bundled PSADT template missing: {_BUNDLED_TEMPLATE_DIR}"
            )
        return _BUNDLED_TEMPLATE_DIR

    def generate(
        self,
        *,
        installer_path: Path,
        output_dir: Path,
        product_name: str = "",
        installer_type: str = "",
        detection_candidates: List[DetectionCandidate] | None = None,
        close_apps: List[str] | None = None,
    ) -> Path:
        """
        Build a PSADT wrapper directory under *output_dir*/psadt_wrapper/.

        Returns the path to the wrapper directory.
        """
        installer_path = Path(installer_path)
        if not installer_path.is_file():
            raise PsadtWrapperError(f"Installer not found: {installer_path}")

        wrapper_dir = Path(output_dir) / "psadt_wrapper"
        wrapper_dir.mkdir(parents=True, exist_ok=True)

        toolkit_src = self._resolve_toolkit_dir()
        toolkit_dst = wrapper_dir / "AppDeployToolkit"
        if toolkit_dst.exists():
            shutil.rmtree(toolkit_dst)
        shutil.copytree(str(toolkit_src), str(toolkit_dst))
        logger.info("Copied PSADT toolkit from %s", toolkit_src)

        files_dir = wrapper_dir / "Files"
        files_dir.mkdir(exist_ok=True)
        staged_installer = files_dir / installer_path.name
        staged_installer.write_bytes(installer_path.read_bytes())
        logger.info("Staged installer: %s", staged_installer)

        deploy_ps1 = wrapper_dir / "Deploy-Application.ps1"
        deploy_ps1.write_text(
            self._render_deploy_application(
                installer_filename=installer_path.name,
                product_name=product_name or installer_path.stem,
                installer_type=installer_type,
                close_apps=close_apps or [],
            ),
            encoding="utf-8",
        )

        detect_ps1 = wrapper_dir / "detect.ps1"
        detect_ps1.write_text(
            _render_detect_ps1(detection_candidates or []),
            encoding="utf-8",
        )

        if self._config.serviceui_path:
            sui = Path(self._config.serviceui_path)
            if sui.is_file():
                shutil.copy2(str(sui), str(wrapper_dir / sui.name))
                logger.info("Copied ServiceUI: %s", sui)

        logger.info("PSADT wrapper generated at %s", wrapper_dir)
        return wrapper_dir

    def _render_deploy_application(
        self,
        *,
        installer_filename: str,
        product_name: str,
        installer_type: str,
        close_apps: List[str],
    ) -> str:
        close_apps_str = ",".join(a.strip() for a in close_apps if a.strip())
        close_line = (
            f"    Show-InstallationWelcome -CloseApps '{close_apps_str}' -CloseAppsCountdown 120"
            if close_apps_str
            else "    # No conflicting apps to close"
        )

        progress_line = (
            "    Show-InstallationProgress -StatusMessage \"Installing $appName — please wait…\""
            if self._config.show_progress
            else "    # Progress display disabled"
        )

        reboot_handling = (
            "    if ($result -eq 3010 -or $result -eq 1641) {\n"
            "        Write-Log 'Reboot required/initiated by installer.'\n"
            "        Exit-Script -ExitCode $result\n"
            "    }"
            if self._config.allow_reboot_passthrough
            else (
                "    if ($result -eq 3010 -or $result -eq 1641) {\n"
                "        Write-Log 'Reboot required — suppressing for Intune (exit 0).'\n"
                "        $result = 0\n"
                "    }"
            )
        )

        safe_name = product_name.replace("'", "''")
        safe_type = installer_type.replace("'", "''") if installer_type else "Unknown"
        safe_filename = installer_filename.replace("'", "''")

        return (
            '<#\n'
            '.SYNOPSIS\n'
            f'    PSADT wrapper for "{safe_name}" generated by pkgprobe.\n'
            '.DESCRIPTION\n'
            f'    Installer type: {safe_type}\n'
            '    This wrapper runs the original installer in GUI mode (no silent\n'
            '    switches) via the PSADT toolkit, suitable for Intune Win32\n'
            '    deployment with ServiceUI or user-context execution.\n'
            '#>\n'
            '\n'
            '[CmdletBinding()]\n'
            'param(\n'
            '    [ValidateSet("Install","Uninstall","Repair")]\n'
            '    [string]$DeploymentType = "Install",\n'
            '    [ValidateSet("Interactive","Silent","NonInteractive")]\n'
            '    [string]$DeployMode = "Interactive",\n'
            '    [switch]$AllowRebootPassThru,\n'
            '    [switch]$TerminalServerMode\n'
            ')\n'
            '\n'
            'try {\n'
            '    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path\n'
            '    . "$scriptDirectory\\AppDeployToolkit\\AppDeployToolkitMain.ps1"\n'
            '} catch {\n'
            '    Write-Error "Failed to load PSADT toolkit: $_"\n'
            '    exit 60001\n'
            '}\n'
            '\n'
            f"$appName    = '{safe_name}'\n"
            f"$appVersion = '1.0'\n"
            f"$appVendor  = ''\n"
            '\n'
            'Initialize-Logging -AppName ($appName -replace "[^a-zA-Z0-9_-]", "_")\n'
            '\n'
            '# ======================================================================\n'
            '# PRE-INSTALLATION\n'
            '# ======================================================================\n'
            f'{close_line}\n'
            f'{progress_line}\n'
            '\n'
            '# ======================================================================\n'
            '# INSTALLATION\n'
            '# ======================================================================\n'
            f"$installerPath = Join-Path (Join-Path $scriptDirectory 'Files') '{safe_filename}'\n"
            "Write-Log \"Running installer: $installerPath\"\n"
            '\n'
            "$result = Execute-Process -Path $installerPath -PassThru\n"
            "if ($result -is [System.Diagnostics.Process]) {\n"
            "    $result = $result.ExitCode\n"
            "}\n"
            '\n'
            f'{reboot_handling}\n'
            '\n'
            '# ======================================================================\n'
            '# POST-INSTALLATION\n'
            '# ======================================================================\n'
            'Close-InstallationProgress\n'
            '\n'
            "if ($result -ne 0) {\n"
            "    Write-Log \"Installer exited with code $result\" -Severity Error\n"
            "    Exit-Script -ExitCode $result\n"
            "}\n"
            '\n'
            "Write-Log 'Installation completed successfully.'\n"
            "Exit-Script -ExitCode 0\n"
        )


def _render_detect_ps1(candidates: list[DetectionCandidate]) -> str:
    """Same logic as IntuneWinPackager._render_detect_ps1 for consistency."""
    best = None
    for c in candidates:
        if best is None or float(c.confidence) > float(best.confidence):
            best = c

    if best is None:
        return "exit 1\n"

    if best.type in ("registry_key", "msi_product_code"):
        path = best.value
        path = path.replace("HKLM\\", "HKLM:\\").replace("HKCU\\", "HKCU:\\")
        return (
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            f'if (Test-Path "{path}") {{ exit 0 }}\n'
            "exit 1\n"
        )
    if best.type == "file_exists":
        return (
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            f'if (Test-Path "{best.value}") {{ exit 0 }}\n'
            "exit 1\n"
        )
    if best.type == "service_exists":
        return (
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            f'$s = Get-Service -Name "{best.value}" -ErrorAction SilentlyContinue\n'
            "if ($null -ne $s) { exit 0 }\n"
            "exit 1\n"
        )
    if best.type == "scheduled_task_exists":
        return (
            "$ErrorActionPreference = 'SilentlyContinue'\n"
            f'$t = Get-ScheduledTask -TaskName "{best.value}" -ErrorAction SilentlyContinue\n'
            "if ($null -ne $t) { exit 0 }\n"
            "exit 1\n"
        )

    return "exit 1\n"
