"""
Installer upload and execution inside the guest VM.

This module is intentionally generic: the caller specifies silent arguments,
timeouts, and the guest destination path.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import List, Optional

from .vmware_controller import VMwareController, VMwareControllerError

logger = logging.getLogger(__name__)


class InstallerExecutorError(RuntimeError):
    """Raised when installer upload or execution fails."""


@dataclass(frozen=True)
class InstallerExecutionConfig:
    guest_installer_path: str = r"C:\trace\installer.exe"
    silent_args: Optional[List[str]] = None
    timeout_sec: int = 120
    """Hard cap for vmrun waiting on the primary installer process (host-side)."""
    installer_tail_wait_sec: int = 600
    """After the main installer returns, wait up to this long for msiexec to finish."""
    installer_quiet_window_sec: int = 10
    """Require this many quiet seconds before declaring install completion."""
    installer_min_runtime_sec: int = 0
    """Do not declare completion earlier than this many seconds into tail wait."""
    diagnostics_level: str = "normal"
    guest_diag_after_installer: bool = True
    """Log tasklist / wmic in guest after installer (debug MSI stuck scenarios)."""


def _encode_powershell_command(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


class InstallerExecutor:
    def __init__(self, vmware: VMwareController, config: InstallerExecutionConfig) -> None:
        self._vmware = vmware
        self._config = config

    @property
    def guest_installer_path(self) -> str:
        return self._config.guest_installer_path

    def upload_installer(self, host_installer_path: str) -> None:
        try:
            logger.info(
                "Uploading installer %s -> %s",
                host_installer_path,
                self._config.guest_installer_path,
            )
            self._vmware.copy_file_to_guest(host_installer_path, self._config.guest_installer_path)
        except (OSError, VMwareControllerError) as exc:
            raise InstallerExecutorError(f"Failed to upload installer: {host_installer_path}") from exc

    def _merge_msi_args(self, args: List[str]) -> List[str]:
        lower = {a.lower() for a in args}
        out = list(args)
        if "/norestart" not in lower and "-norestart" not in lower:
            out.append("/norestart")
        has_log = any(a.lower().startswith("/log") or a.lower().startswith("-log") for a in out)
        if not has_log:
            out.extend(["/log", r"C:\trace\logs\msi_install.log"])
        return out

    def run_installer_silent(self) -> None:
        args: List[str] = []
        if self._config.silent_args:
            args.extend(self._config.silent_args)

        guest_path = self._config.guest_installer_path
        logger.info("Running installer: %s %s", guest_path, " ".join(args))

        timeout = int(self._config.timeout_sec)

        try:
            # For MSI payloads, invoke msiexec explicitly; vmrun cannot execute an .msi directly.
            if guest_path.lower().endswith(".msi"):
                full_args: List[str] = ["/i", guest_path]
                full_args.extend(self._merge_msi_args(args))
                proc = self._vmware.run_program_in_guest(
                    r"C:\Windows\System32\msiexec.exe",
                    args=full_args,
                    timeout_sec=timeout,
                    check=False,
                )
            else:
                proc = self._vmware.run_program_in_guest(
                    guest_path,
                    args=args,
                    timeout_sec=timeout,
                    check=False,
                )
        except VMwareControllerError as exc:
            if "timed out" in str(exc).lower():
                raise InstallerExecutorError(
                    f"Installer timed out after {timeout}s (vmrun guest run)"
                ) from exc
            raise InstallerExecutorError(f"Installer vmrun failed: {exc}") from exc

        if proc.returncode != 0:
            raise InstallerExecutorError(
                f"Installer returned exit code {proc.returncode} (stdout={proc.stdout!r}, stderr={proc.stderr!r})"
            )

    def log_guest_installer_diagnostics(self) -> None:
        """Capture tasklist + wmic process snapshot inside the guest (logged, not persisted)."""
        probes: list[tuple[str, str, list[str]]] = [
            ("tasklist", r"C:\Windows\System32\cmd.exe", ["/c", "tasklist"]),
            (
                "wmic_processes",
                r"C:\Windows\System32\cmd.exe",
                ["/c", "wmic", "process", "get", "name,processid", "/format:list"],
            ),
        ]
        if self._config.diagnostics_level == "deep":
            probes.extend(
                [
                    ("services_query", r"C:\Windows\System32\cmd.exe", ["/c", "sc", "query", "state=", "all"]),
                    ("pending_reboot_keys", r"C:\Windows\System32\cmd.exe", ["/c", "reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"]),
                ]
            )
        for label, program, pargs in probes:
            try:
                proc = self._vmware.run_program_in_guest(
                    program,
                    args=pargs,
                    timeout_sec=120,
                    check=False,
                )
                text = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
                logger.info(
                    "Guest %s (exit=%s, first 12k chars):\n%s",
                    label,
                    proc.returncode,
                    text[:12000],
                )
            except VMwareControllerError as exc:
                logger.warning("Guest diagnostic %s failed: %s", label, exc)

    def wait_for_installer_tail_processes(self) -> None:
        """
        After msiexec / setup returns, msiexec may still run async installs.

        Blocks until no ``msiexec`` process or ``installer_tail_wait_sec`` exceeded.
        """
        max_sec = max(1, int(self._config.installer_tail_wait_sec))
        quiet_sec = max(1, int(self._config.installer_quiet_window_sec))
        min_runtime_sec = max(0, int(self._config.installer_min_runtime_sec))
        stem = PureWindowsPath(self._config.guest_installer_path).stem.lower()
        # Completion detection:
        # - strong: no msiexec processes
        # - fallback: installer stem + common setup process names also quiet
        # Require a short quiet window to avoid transient process respawns.
        script = f"""
$deadline = (Get-Date).AddSeconds({max_sec})
$minDone = (Get-Date).AddSeconds({min_runtime_sec})
$quietStart = $null
$stem = "{stem}"
while ($true) {{
  $procs = @(Get-Process -ErrorAction SilentlyContinue)
  $active = @($procs | Where-Object {{
    $n = $_.ProcessName.ToLowerInvariant()
    $n -eq "msiexec" -or
    ($stem.Length -ge 3 -and ($n -eq $stem -or $n.StartsWith($stem))) -or
    $n -eq "setup" -or
    $n -eq "installer" -or
    $n -eq "isbew64" -or
    $n -eq "isbew32"
  }})

  if ($active.Count -eq 0) {{
    if ($quietStart -eq $null) {{
      $quietStart = Get-Date
    }}
    if ((Get-Date) -lt $minDone) {{
      Start-Sleep -Seconds 1
      continue
    }}
    if (((Get-Date) - $quietStart).TotalSeconds -ge {quiet_sec}) {{
      exit 0
    }}
  }} else {{
    $quietStart = $null
  }}

  if ((Get-Date) -gt $deadline) {{ exit 2 }}
  Start-Sleep -Seconds 1
}}
exit 0
"""
        enc = _encode_powershell_command(script)
        ps_args = [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            enc,
        ]
        # Host waits slightly longer than guest script deadline for vmrun overhead.
        try:
            proc = self._vmware.run_program_in_guest(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                args=ps_args,
                timeout_sec=max_sec + 60,
                check=False,
            )
        except VMwareControllerError as exc:
            raise InstallerExecutorError(f"Wait for installer tail failed: {exc}") from exc

        if proc.returncode == 2:
            raise InstallerExecutorError(
                f"Installer tail did not settle after {max_sec}s (msiexec/setup process activity still present)"
            )
        if proc.returncode != 0:
            raise InstallerExecutorError(
                f"Installer tail wait returned {proc.returncode} (stdout={proc.stdout!r}, stderr={proc.stderr!r})"
            )
