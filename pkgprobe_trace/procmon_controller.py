"""
ProcMon control inside the guest VM.

We start/stop ProcMon inside the Windows guest via `vmrun runProgramInGuest`.
We also support exporting a captured PML log to CSV (PML→CSV) in the guest so
the host can parse it deterministically.
"""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from .vmware_controller import VMwareController

logger = logging.getLogger(__name__)


def export_pml_to_csv_on_host(
    *,
    host_pml_path: str,
    host_csv_path: str,
    procmon_exe: str,
    quiet: bool = True,
    timeout_sec: int = 180,
) -> subprocess.CompletedProcess:
    """
    Run ProcMon on the host to convert a PML copied from the guest to CSV.

    Requires Windows and a local ``procmon.exe`` (same Sysinternals build as
    in the guest is ideal). Falls back to guest-side export when omitted.
    """
    if not os.path.isfile(host_pml_path):
        raise FileNotFoundError(host_pml_path)
    host_csv_dir = os.path.dirname(host_csv_path)
    if host_csv_dir and not os.path.isdir(host_csv_dir):
        os.makedirs(host_csv_dir, exist_ok=True)

    args: List[str] = [procmon_exe, "/AcceptEula"]
    if quiet:
        args.append("/Quiet")
    args.extend(["/OpenLog", host_pml_path, "/SaveAs", host_csv_path])

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    logger.info("Host ProcMon PML->CSV: %s -> %s", host_pml_path, host_csv_path)
    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
        creationflags=creationflags,
    )
    if proc.returncode != 0:
        logger.warning(
            "Host ProcMon export returned %s (stdout=%r stderr=%r)",
            proc.returncode,
            proc.stdout,
            proc.stderr,
        )
    return proc


@dataclass(frozen=True)
class ProcmonConfig:
    """
    ProcMon settings (guest-side).

    Attributes
    ----------
    procmon_path:
        Path to `procmon.exe` in the guest.
    backing_pml:
        ProcMon backing file to write (PML path in guest).
    quiet:
        If True, includes `/Quiet` in ProcMon invocations.
    export_csv_timeout_sec:
        Timeout for PML→CSV export.
    """

    procmon_path: str = r"C:\trace\tools\procmon.exe"
    backing_pml: str = r"C:\trace\logs\trace.pml"
    quiet: bool = True
    export_csv_timeout_sec: int = 180
    profile: str = "balanced"
    tuning_json: str = ""


class ProcmonController:
    """
    Start/stop ProcMon and export PML→CSV inside the guest.

    ProcMon CLI behavior varies slightly by version; the export method is
    implemented as a best-effort deterministic call:
    `procmon.exe /Quiet /OpenLog <pml> /SaveAs <csv>`

    If your ProcMon build uses different flags, adjust `export_pml_to_csv`.
    """

    def __init__(self, vmware: VMwareController, config: ProcmonConfig) -> None:
        self._vmware = vmware
        self._config = config

    def start_capture(self) -> None:
        args: List[str] = []
        args.append("/AcceptEula")
        if self._config.quiet:
            args.append("/Quiet")
        args.extend(["/BackingFile", self._config.backing_pml])

        logger.info(
            "Starting ProcMon capture -> %s (profile=%s)",
            self._config.backing_pml,
            self._config.profile,
        )
        self._vmware.run_program_in_guest(
            self._config.procmon_path,
            args=args,
            no_wait=True,
            check=False,
        )

    def stop_capture(self) -> None:
        args: List[str] = []
        if self._config.quiet:
            args.append("/Quiet")
        args.append("/Terminate")

        logger.info("Stopping ProcMon capture")
        self._vmware.run_program_in_guest(self._config.procmon_path, args=args, check=False)

    def export_pml_to_csv(self, guest_csv_path: str) -> None:
        """
        Export the configured PML backing file to a CSV inside the guest.

        Parameters
        ----------
        guest_csv_path:
            Output CSV path in the guest (e.g. C:\\trace\\logs\\trace.csv).
        """
        args: List[str] = []
        if self._config.quiet:
            args.append("/Quiet")
        args.extend(
            [
                "/OpenLog",
                self._config.backing_pml,
                "/SaveAs",
                guest_csv_path,
            ]
        )

        logger.info("Exporting ProcMon PML->CSV: %s -> %s", self._config.backing_pml, guest_csv_path)
        proc = self._vmware.run_program_in_guest(
            self._config.procmon_path,
            args=args,
            timeout_sec=self._config.export_csv_timeout_sec,
            check=False,
        )
        if proc.returncode != 0:
            # ProcMon sometimes returns non-zero while still producing output;
            # we leave final validation to the host-side copy/parse steps.
            logger.warning(
                "ProcMon export returned %s (stdout=%r stderr=%r)",
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )

