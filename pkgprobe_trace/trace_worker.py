"""
TraceWorker orchestrates an end-to-end trace run:

1. Revert VM snapshot
2. Start VM
3. Upload installer
4. Start ProcMon capture
5. Run installer silently
6. Stop ProcMon
7. Export PML→CSV inside guest
8. Copy trace artifacts back to host
9. Parse diff and produce an InstallPlan
10. Revert snapshot (finally)

This worker is designed for local VMware Workstation today, but the interface
is intentionally dependency-injected so it can later run in cloud VM workers.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from .diff_engine import DiffEngine, DiffResult
from .installer_executor import InstallerExecutor
from .installplan_generator import InstallPlan
from .manifest_builder import build_verified_manifest
from .procmon_controller import ProcmonController
from .verified_manifest import VerifiedTraceManifest
from .vmware_controller import VMwareController, VMwareControllerError

logger = logging.getLogger(__name__)


class TraceWorkerError(RuntimeError):
    """Raised for trace failures."""


@dataclass(frozen=True)
class TraceWorkerConfig:
    host_output_dir: str

    guest_pml_path: str = r"C:\trace\logs\trace.pml"
    guest_csv_path: str = r"C:\trace\logs\trace.csv"

    host_pml_name: str = "trace.pml"
    host_csv_name: str = "trace.csv"

    boot_wait_sec: int = 30


class TraceWorker:
    def __init__(
        self,
        *,
        vmware: VMwareController,
        procmon: ProcmonController,
        installer_executor: InstallerExecutor,
        diff_engine: DiffEngine,
        config: TraceWorkerConfig,
    ) -> None:
        self._vmware = vmware
        self._procmon = procmon
        self._installer_executor = installer_executor
        self._diff_engine = diff_engine
        self._config = config

    def run_trace(
        self,
        *,
        host_installer_path: str,
        install_command_display: str,
    ) -> Tuple[InstallPlan, DiffResult]:
        """
        Run a full trace and return an InstallPlan.

        Parameters
        ----------
        host_installer_path:
            Path to installer binary on the host.
        install_command_display:
            String captured into InstallPlan metadata (what you intended to run).
        """
        os.makedirs(self._config.host_output_dir, exist_ok=True)
        host_pml_path = os.path.join(self._config.host_output_dir, self._config.host_pml_name)
        host_csv_path = os.path.join(self._config.host_output_dir, self._config.host_csv_name)

        try:
            logger.info("Reverting to clean snapshot")
            self._vmware.revert_snapshot()

            logger.info("Starting VM")
            self._vmware.start_vm(nogui=True)

            logger.info("Waiting for guest boot: %ss", self._config.boot_wait_sec)
            time.sleep(self._config.boot_wait_sec)

            logger.info("Uploading installer")
            self._installer_executor.upload_installer(host_installer_path)

            logger.info("Starting ProcMon capture")
            self._procmon.start_capture()

            logger.info("Running installer")
            self._installer_executor.run_installer_silent()

            logger.info("Stopping ProcMon capture")
            self._procmon.stop_capture()

            logger.info("Exporting PML->CSV inside guest")
            self._procmon.export_pml_to_csv(self._config.guest_csv_path)

            logger.info("Copying PML back to host: %s", host_pml_path)
            self._vmware.copy_file_from_guest(self._config.guest_pml_path, host_pml_path)

            logger.info("Copying CSV back to host: %s", host_csv_path)
            self._vmware.copy_file_from_guest(self._config.guest_csv_path, host_csv_path)

            diff: DiffResult = self._diff_engine.build_diff_from_procmon_csv(host_csv_path)
            plan = InstallPlan.from_diff(install_command=install_command_display, diff=diff)
            return plan, diff
        except Exception as exc:
            logger.exception("Trace failed")
            raise TraceWorkerError(str(exc)) from exc
        finally:
            try:
                logger.info("Reverting snapshot (cleanup)")
                self._vmware.revert_snapshot()
            except VMwareControllerError:
                logger.warning("Snapshot revert failed during cleanup")

    def run_trace_with_manifest(
        self,
        *,
        host_installer_path: str,
        install_command_display: str,
        installer_filename: str,
        install_exe_name: str,
        silent_args: list[str] | None = None,
    ) -> tuple[InstallPlan, VerifiedTraceManifest]:
        plan, diff = self.run_trace(
            host_installer_path=host_installer_path,
            install_command_display=install_command_display,
        )
        manifest = build_verified_manifest(
            plan=plan,
            diff=diff,
            installer_filename=installer_filename,
            install_exe_name=install_exe_name,
            silent_args=silent_args,
        )
        return plan, manifest

