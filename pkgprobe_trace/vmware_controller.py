"""
VMware VM lifecycle and guest-command control for pkgprobe Trace.

This module wraps the `vmrun` CLI (VMware Workstation Pro) in a safe, logged API
that can later be swapped for other VM backends (e.g. cloud VMs).

Design goals
------------
- Deterministic control flow: explicit timeouts and clear error surfaces.
- Secure subprocess usage: no shell=True, args passed as a list.
- Integration-ready: small public surface area and dependency injection.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


class VMwareControllerError(RuntimeError):
    """Base error raised by VMwareController operations."""


@dataclass(frozen=True)
class VMwareControllerConfig:
    """
    Configuration for controlling a single VMware VM instance.

    Attributes
    ----------
    vmx_path:
        Absolute path to the .vmx file for the trace VM.
    snapshot_name:
        Name of the "clean" baseline snapshot to revert to (e.g. TRACE_BASE).
    guest_username:
        Windows username in the guest for vmrun guest operations.
    guest_password:
        Windows password in the guest for vmrun guest operations.
    vmrun_path:
        Path to `vmrun`. Defaults to "vmrun" (resolved via PATH).
    default_timeout_sec:
        Default timeout for vmrun commands.
    """

    vmx_path: str
    snapshot_name: str
    guest_username: str
    guest_password: str
    vmrun_path: str = "vmrun"
    default_timeout_sec: int = 300
    vmrun_retries: int = 2
    vmrun_retry_delay_sec: float = 1.0


class VMwareController:
    """
    High-level wrapper around the `vmrun` CLI.

    Note: `run_program_in_guest` returns the vmrun process result, not the exit
    status of the inner guest process. For most trace automation, vmrun success
    is the primary signal; guest exit codes can be surfaced later by writing
    explicit logs inside the guest.
    """

    def __init__(self, config: VMwareControllerConfig) -> None:
        self.config = config

    def check_tools_state(self, timeout_sec: Optional[int] = None) -> str:
        """
        Return vmrun `checkToolsState` output for the VM (typically contains
        ``running``, ``installed``, or ``not installed``).
        """
        args: List[str] = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "checkToolsState",
            self.config.vmx_path,
        ]
        proc = self._run_vmrun(
            args,
            timeout_sec=timeout_sec or 60,
            operation="check_tools_state",
            check=False,
        )
        return (proc.stdout or proc.stderr or "").strip().lower()

    def wait_for_guest_tools(
        self,
        *,
        poll_interval_sec: float = 2.0,
        timeout_sec: int = 120,
    ) -> None:
        """
        Poll until VMware Tools reports a running state, or raise on timeout.

        Replaces a fixed post-boot sleep so fast hosts finish sooner and slow
        disks still get a bounded wait.
        """
        deadline = time.monotonic() + timeout_sec
        last = ""
        while time.monotonic() < deadline:
            last = self.check_tools_state()
            if "running" in last:
                logger.info("Guest VMware Tools ready (%s)", last)
                return
            logger.debug("Guest tools not ready yet: %s", last or "(empty)")
            time.sleep(poll_interval_sec)
        raise VMwareControllerError(
            f"Timed out after {timeout_sec}s waiting for VMware Tools in guest "
            f"(last checkToolsState output: {last!r})"
        )

    def start_vm(self, nogui: bool = True, timeout_sec: Optional[int] = None) -> None:
        args: List[str] = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "start",
            self.config.vmx_path,
        ]
        if nogui:
            args.append("nogui")
        self._run_vmrun(args, timeout_sec=timeout_sec, operation="start_vm", check=True)

    def stop_vm(self, mode: str = "hard", timeout_sec: Optional[int] = None) -> None:
        if mode not in ("soft", "hard"):
            raise ValueError(f"Unsupported stop mode: {mode}")

        args = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "stop",
            self.config.vmx_path,
            mode,
        ]
        self._run_vmrun(args, timeout_sec=timeout_sec, operation="stop_vm", check=True)

    def revert_snapshot(
        self, snapshot_name: Optional[str] = None, timeout_sec: Optional[int] = None
    ) -> None:
        snapshot = snapshot_name or self.config.snapshot_name
        args = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "revertToSnapshot",
            self.config.vmx_path,
            snapshot,
        ]
        self._run_vmrun(
            args, timeout_sec=timeout_sec, operation="revert_snapshot", check=True
        )

    def copy_file_to_guest(
        self, host_path: str, guest_path: str, timeout_sec: Optional[int] = None
    ) -> None:
        if not os.path.isfile(host_path):
            raise FileNotFoundError(host_path)

        args = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "-gu",
            self.config.guest_username,
            "-gp",
            self.config.guest_password,
            "copyFileFromHostToGuest",
            self.config.vmx_path,
            host_path,
            guest_path,
        ]
        self._run_vmrun(
            args, timeout_sec=timeout_sec, operation="copy_file_to_guest", check=True
        )

    def copy_file_from_guest(
        self, guest_path: str, host_path: str, timeout_sec: Optional[int] = None
    ) -> None:
        host_dir = os.path.dirname(host_path)
        if host_dir and not os.path.isdir(host_dir):
            os.makedirs(host_dir, exist_ok=True)

        args = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "-gu",
            self.config.guest_username,
            "-gp",
            self.config.guest_password,
            "copyFileFromGuestToHost",
            self.config.vmx_path,
            guest_path,
            host_path,
        ]
        self._run_vmrun(
            args, timeout_sec=timeout_sec, operation="copy_file_from_guest", check=True
        )

    def run_program_in_guest(
        self,
        program_path: str,
        args: Optional[List[str]] = None,
        *,
        interactive: bool = False,
        no_wait: bool = False,
        timeout_sec: Optional[int] = None,
        check: bool = False,
    ) -> subprocess.CompletedProcess:
        vmrun_args: List[str] = [
            self.config.vmrun_path,
            "-T",
            "ws",
            "-gu",
            self.config.guest_username,
            "-gp",
            self.config.guest_password,
            "runProgramInGuest",
            self.config.vmx_path,
        ]
        if interactive:
            vmrun_args.append("-interactive")
        if no_wait:
            vmrun_args.append("-noWait")

        vmrun_args.append(program_path)
        if args:
            vmrun_args.extend(args)

        return self._run_vmrun(
            vmrun_args,
            timeout_sec=timeout_sec,
            operation="run_program_in_guest",
            check=check,
        )

    def _run_vmrun(
        self,
        args: List[str],
        *,
        timeout_sec: Optional[int],
        operation: str,
        check: bool,
    ) -> subprocess.CompletedProcess:
        timeout = timeout_sec or self.config.default_timeout_sec
        logger.info("vmrun %s: %s", operation, " ".join(args))

        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

        extra = self.config.vmrun_retries if check else 0
        max_attempts = max(1, 1 + extra)
        proc: Optional[subprocess.CompletedProcess] = None

        for attempt in range(1, max_attempts + 1):
            try:
                proc = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    creationflags=creationflags,
                )
            except subprocess.TimeoutExpired as exc:
                if attempt >= max_attempts or not check:
                    raise VMwareControllerError(
                        f"vmrun {operation} timed out after {timeout} seconds"
                    ) from exc
                logger.warning(
                    "vmrun %s timed out (attempt %s/%s), retrying in %ss",
                    operation,
                    attempt,
                    max_attempts,
                    self.config.vmrun_retry_delay_sec,
                )
                time.sleep(self.config.vmrun_retry_delay_sec)
                continue

            assert proc is not None
            if proc.stdout:
                logger.debug("vmrun %s stdout:\n%s", operation, proc.stdout)
            if proc.stderr:
                logger.debug("vmrun %s stderr:\n%s", operation, proc.stderr)

            if check and proc.returncode != 0:
                if attempt < max_attempts:
                    logger.warning(
                        "vmrun %s failed with exit code %s (attempt %s/%s), retrying in %ss",
                        operation,
                        proc.returncode,
                        attempt,
                        max_attempts,
                        self.config.vmrun_retry_delay_sec,
                    )
                    time.sleep(self.config.vmrun_retry_delay_sec)
                    continue
                raise VMwareControllerError(
                    f"vmrun {operation} failed with exit code {proc.returncode}"
                )

            return proc

