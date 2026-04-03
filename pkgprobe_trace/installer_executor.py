"""
Installer upload and execution inside the guest VM.

This module is intentionally generic: the caller specifies silent arguments,
timeouts, and the guest destination path.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from .vmware_controller import VMwareController, VMwareControllerError

logger = logging.getLogger(__name__)


class InstallerExecutorError(RuntimeError):
    """Raised when installer upload or execution fails."""


@dataclass(frozen=True)
class InstallerExecutionConfig:
    guest_installer_path: str = r"C:\trace\installer.exe"
    silent_args: Optional[List[str]] = None
    timeout_sec: int = 1800


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

    def run_installer_silent(self) -> None:
        args: List[str] = []
        if self._config.silent_args:
            args.extend(self._config.silent_args)

        guest_path = self._config.guest_installer_path
        logger.info("Running installer: %s %s", guest_path, " ".join(args))

        # For MSI payloads, invoke msiexec explicitly; vmrun cannot execute an .msi directly.
        if guest_path.lower().endswith(".msi"):
            full_args: List[str] = ["/i", guest_path]
            full_args.extend(args)
            proc = self._vmware.run_program_in_guest(
                r"C:\Windows\System32\msiexec.exe",
                args=full_args,
                timeout_sec=self._config.timeout_sec,
                check=False,
            )
        else:
            # vmrun waits for the guest process unless -noWait is used; capture runs until this returns.
            proc = self._vmware.run_program_in_guest(
                guest_path,
                args=args,
                timeout_sec=self._config.timeout_sec,
                check=False,
            )
        if proc.returncode != 0:
            raise InstallerExecutorError(
                f"Installer returned exit code {proc.returncode} (stdout={proc.stdout!r}, stderr={proc.stderr!r})"
            )

