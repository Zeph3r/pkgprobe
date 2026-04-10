"""
TraceWorker orchestrates an end-to-end trace run:

1. Revert VM snapshot
2. Start VM
3. Upload installer
4. Start ProcMon capture
5. Run installer silently
6. Stop ProcMon
7. Copy PML to host; export PML→CSV on host (if configured) or in guest
8. Copy CSV from guest when guest export was used
9. Parse diff and produce an InstallPlan
10. Revert snapshot (finally)

This worker is designed for local VMware Workstation today, but the interface
is intentionally dependency-injected so it can later run in cloud VM workers.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple

from .diff_engine import DiffEngine, DiffResult
from .installer_executor import InstallerExecutor, InstallerExecutorError
from .installplan_generator import InstallPlan
from .manifest_builder import build_draft_manifest, collect_detection_candidates
from .trace_contract import write_trace_contract_file
from .procmon_controller import ProcmonController, export_pml_to_csv_on_host
from .psadt_wrapper import PsadtWrapperConfig, PsadtWrapperGenerator
from .trace_progress import (
    STAGE_BOOTING_VM,
    STAGE_EXPORTING_TRACE,
    STAGE_GENERATING_OUTPUT,
    STAGE_GENERATING_WRAPPER,
    STAGE_PARSING,
    STAGE_RUNNING_INSTALLER,
    STAGE_STOPPING_PROCMON,
    STAGE_UPLOADING,
    STAGE_VERIFYING_WRAPPER,
    TraceProgressError,
    TraceStageTracker,
)
from .verified_manifest import DetectionCandidate, VerifiedTraceManifest
from .vmware_controller import VMwareController, VMwareControllerError
from .wrapper_verifier import WrapperVerifier, WrapperVerifierConfig

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

    guest_tools_timeout_sec: int = 120
    guest_tools_poll_interval_sec: float = 2.0
    boot_wait_sec: int = 0

    pause_after_trace: bool = False
    """If True, skip snapshot revert after the run (leave VM up for inspection)."""

    host_procmon_path: str | None = None
    """If set, copy PML to the host first and export CSV with this ProcMon binary."""

    baseline_csv_path: str | None = None
    """Optional host path to a baseline ProcMon CSV (e.g. idle VM) to subtract from the install trace."""
    baseline_subtraction: bool = True
    baseline_max_age_hours: float = 0.0
    verification_strictness: str = "balanced"
    noise_strictness: str = "balanced"

    stuck_stage_timeout_sec: float = 900.0
    """Fail if a single stage does not advance within this many seconds."""
    trace_wall_clock_sec: float = 0.0
    """0 = disabled. Otherwise fail the whole trace after this many seconds."""
    guest_installer_diag: bool = True
    stage_timeout_boot_sec: float = 0.0
    stage_timeout_installer_sec: float = 0.0
    stage_timeout_export_sec: float = 0.0
    stage_timeout_parse_sec: float = 0.0
    stage_timeout_pack_sec: float = 0.0
    diagnostics_level: str = "normal"

    auto_wrap: bool = False
    """When True and silent install fails, generate a PSADT wrapper and verify it."""
    psadt_wrapper_config: PsadtWrapperConfig | None = None
    wrapper_verify_config: WrapperVerifierConfig | None = None


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

    def _execute_trace_core(
        self,
        *,
        host_installer_path: str,
        install_command_display: str,
        tracker: TraceStageTracker,
    ) -> Tuple[InstallPlan, DiffResult]:
        os.makedirs(self._config.host_output_dir, exist_ok=True)
        host_pml_path = os.path.join(self._config.host_output_dir, self._config.host_pml_name)
        host_csv_path = os.path.join(self._config.host_output_dir, self._config.host_csv_name)

        tracker.set_stage(STAGE_BOOTING_VM)
        logger.info("Reverting to clean snapshot")
        self._vmware.revert_snapshot()

        logger.info("Starting VM")
        self._vmware.start_vm(nogui=True)

        logger.info(
            "Waiting for VMware Tools in guest (timeout=%ss, poll=%ss)",
            self._config.guest_tools_timeout_sec,
            self._config.guest_tools_poll_interval_sec,
        )
        self._vmware.wait_for_guest_tools(
            poll_interval_sec=self._config.guest_tools_poll_interval_sec,
            timeout_sec=self._config.guest_tools_timeout_sec,
        )
        tracker.touch()
        if self._config.boot_wait_sec > 0:
            logger.info("Extra boot wait: %ss", self._config.boot_wait_sec)
            time.sleep(self._config.boot_wait_sec)

        tracker.set_stage(STAGE_UPLOADING)
        logger.info("Uploading installer")
        self._installer_executor.upload_installer(host_installer_path)

        tracker.set_stage(STAGE_RUNNING_INSTALLER)
        logger.info("Starting ProcMon capture")
        stop_pulse = threading.Event()
        pulse_err: list[BaseException | None] = [None]
        raised: list[BaseException] = []

        def _pulse_loop() -> None:
            while not stop_pulse.wait(15.0):
                try:
                    tracker.touch()
                except BaseException as exc:  # noqa: BLE001
                    pulse_err[0] = exc
                    return

        pulser = threading.Thread(target=_pulse_loop, name="trace-stage-pulse", daemon=True)
        pulser.start()
        try:
            self._procmon.start_capture()

            logger.info("Running installer")
            try:
                self._installer_executor.run_installer_silent()
            except InstallerExecutorError:
                raise
            except Exception as exc:
                raise InstallerExecutorError(str(exc)) from exc

            if self._config.guest_installer_diag:
                self._installer_executor.log_guest_installer_diagnostics()

            logger.info("Waiting for installer tail processes (msiexec, etc.)")
            self._installer_executor.wait_for_installer_tail_processes()
        except BaseException as exc:
            raised.append(exc)
            raise
        finally:
            stop_pulse.set()
            pulser.join(timeout=3.0)
            if not raised and pulse_err[0] is not None:
                raise pulse_err[0]

        tracker.set_stage(STAGE_STOPPING_PROCMON)
        logger.info("Stopping ProcMon capture")
        self._procmon.stop_capture()

        tracker.set_stage(STAGE_EXPORTING_TRACE)
        logger.info("Copying PML back to host: %s", host_pml_path)
        self._vmware.copy_file_from_guest(self._config.guest_pml_path, host_pml_path)

        if self._config.host_procmon_path:
            logger.info(
                "Exporting PML->CSV on host via %s", self._config.host_procmon_path
            )
            try:
                res = export_pml_to_csv_on_host(
                    host_pml_path=host_pml_path,
                    host_csv_path=host_csv_path,
                    procmon_exe=self._config.host_procmon_path,
                )
                if res.returncode != 0 or not os.path.isfile(host_csv_path):
                    raise OSError(
                        f"host ProcMon export failed (code={res.returncode}, csv exists={os.path.isfile(host_csv_path)})"
                    )
            except OSError as exc:
                logger.warning(
                    "Host ProcMon export failed (%s); falling back to guest export",
                    exc,
                )
                self._procmon.export_pml_to_csv(self._config.guest_csv_path)
                self._vmware.copy_file_from_guest(self._config.guest_csv_path, host_csv_path)
        else:
            logger.info("Exporting PML->CSV inside guest")
            self._procmon.export_pml_to_csv(self._config.guest_csv_path)
            logger.info("Copying CSV back to host: %s", host_csv_path)
            self._vmware.copy_file_from_guest(self._config.guest_csv_path, host_csv_path)

        tracker.touch()
        tracker.set_stage(STAGE_PARSING)
        baseline = self._config.baseline_csv_path if self._config.baseline_subtraction else None
        if baseline and self._config.baseline_max_age_hours > 0:
            p = Path(baseline)
            if p.is_file():
                age_hours = (time.time() - p.stat().st_mtime) / 3600.0
                if age_hours > self._config.baseline_max_age_hours:
                    logger.warning(
                        "Baseline CSV is stale (%.1fh > %.1fh); skipping subtraction",
                        age_hours,
                        self._config.baseline_max_age_hours,
                    )
                    baseline = None
        diff = self._diff_engine.build_diff_from_procmon_csvs(
            [host_csv_path],
            baseline_csv_paths=[baseline] if baseline else None,
        )

        tracker.set_stage(STAGE_GENERATING_OUTPUT)
        plan = InstallPlan.from_diff(install_command=install_command_display, diff=diff)
        return plan, diff

    def _stage_timeout_map(self) -> dict[str, float]:
        return {
            STAGE_BOOTING_VM: float(self._config.stage_timeout_boot_sec),
            STAGE_RUNNING_INSTALLER: float(self._config.stage_timeout_installer_sec),
            STAGE_EXPORTING_TRACE: float(self._config.stage_timeout_export_sec),
            STAGE_PARSING: float(self._config.stage_timeout_parse_sec),
            STAGE_GENERATING_OUTPUT: float(self._config.stage_timeout_pack_sec),
        }

    def run_trace(
        self,
        *,
        host_installer_path: str,
        install_command_display: str,
    ) -> Tuple[InstallPlan, DiffResult]:
        tracker = TraceStageTracker(
            self._config.host_output_dir,
            stuck_stage_timeout_sec=self._config.stuck_stage_timeout_sec,
            wall_clock_sec=self._config.trace_wall_clock_sec,
            stage_timeouts_sec=self._stage_timeout_map(),
        )
        try:
            try:
                return self._execute_trace_core(
                    host_installer_path=host_installer_path,
                    install_command_display=install_command_display,
                    tracker=tracker,
                )
            except TraceProgressError as exc:
                logger.exception("Trace limit exceeded")
                raise TraceWorkerError(str(exc)) from exc
            except InstallerExecutorError as exc:
                logger.exception("Trace failed (installer)")
                raise TraceWorkerError(str(exc)) from exc
            except Exception as exc:
                logger.exception("Trace failed")
                raise TraceWorkerError(str(exc)) from exc
        finally:
            if self._config.pause_after_trace:
                logger.warning(
                    "Skipping snapshot revert (pause-after); VM left in post-trace state"
                )
            else:
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
        tracker = TraceStageTracker(
            self._config.host_output_dir,
            stuck_stage_timeout_sec=self._config.stuck_stage_timeout_sec,
            wall_clock_sec=self._config.trace_wall_clock_sec,
            stage_timeouts_sec=self._stage_timeout_map(),
        )
        try:
            try:
                plan, diff = self._execute_trace_core(
                    host_installer_path=host_installer_path,
                    install_command_display=install_command_display,
                    tracker=tracker,
                )
                tracker.set_stage(STAGE_GENERATING_OUTPUT)
                write_trace_contract_file(
                    self._config.host_output_dir,
                    install_plan_dict=plan.to_json_dict(),
                    diff_dict=diff.to_json_dict(),
                    installer_filename=installer_filename,
                    install_exe_name=install_exe_name,
                    silent_args=list(silent_args or []),
                    verification_strictness=self._config.verification_strictness,
                )
                manifest = build_draft_manifest(
                    plan=plan,
                    diff=diff,
                    installer_filename=installer_filename,
                    install_exe_name=install_exe_name,
                    silent_args=silent_args,
                )
                return plan, manifest
            except TraceProgressError as exc:
                logger.exception("Trace limit exceeded")
                raise TraceWorkerError(str(exc)) from exc
            except InstallerExecutorError as exc:
                logger.exception("Trace failed (installer)")
                raise TraceWorkerError(str(exc)) from exc
            except Exception as exc:
                logger.exception("Trace failed")
                raise TraceWorkerError(str(exc)) from exc
        finally:
            if self._config.pause_after_trace:
                logger.warning(
                    "Skipping snapshot revert (pause-after); VM left in post-trace state"
                )
            else:
                try:
                    logger.info("Reverting snapshot (cleanup)")
                    self._vmware.revert_snapshot()
                except VMwareControllerError:
                    logger.warning("Snapshot revert failed during cleanup")

    # ------------------------------------------------------------------
    # PSADT wrapper fallback
    # ------------------------------------------------------------------

    def run_trace_with_wrapper_fallback(
        self,
        *,
        host_installer_path: str,
        install_command_display: str,
        installer_filename: str,
        install_exe_name: str,
        silent_args: list[str] | None = None,
        product_name: str = "",
        installer_type: str = "",
        detection_candidates: list[DetectionCandidate] | None = None,
    ) -> tuple[InstallPlan, VerifiedTraceManifest, bool]:
        """
        Try a normal trace-with-manifest first.  If the installer fails *and*
        ``auto_wrap`` is enabled, fall back to PSADT wrapper packaging:
        generate the wrapper, verify it in a clean VM, and return a
        wrapper-verified manifest.

        Returns ``(plan, manifest, was_wrapped)``.
        """
        tracker = TraceStageTracker(
            self._config.host_output_dir,
            stuck_stage_timeout_sec=self._config.stuck_stage_timeout_sec,
            wall_clock_sec=self._config.trace_wall_clock_sec,
            stage_timeouts_sec=self._stage_timeout_map(),
        )

        installer_error: InstallerExecutorError | None = None
        plan: InstallPlan | None = None
        diff: DiffResult | None = None

        try:
            try:
                plan, diff = self._execute_trace_core(
                    host_installer_path=host_installer_path,
                    install_command_display=install_command_display,
                    tracker=tracker,
                )
            except InstallerExecutorError as exc:
                installer_error = exc
                logger.warning(
                    "Silent install failed (%s); checking wrapper fallback",
                    exc,
                )
            except TraceProgressError as exc:
                raise TraceWorkerError(str(exc)) from exc
            except Exception as exc:
                raise TraceWorkerError(str(exc)) from exc

            # --- Happy path: silent install succeeded ---
            if plan is not None and diff is not None:
                tracker.set_stage(STAGE_GENERATING_OUTPUT)
                write_trace_contract_file(
                    self._config.host_output_dir,
                    install_plan_dict=plan.to_json_dict(),
                    diff_dict=diff.to_json_dict(),
                    installer_filename=installer_filename,
                    install_exe_name=install_exe_name,
                    silent_args=list(silent_args or []),
                    verification_strictness=self._config.verification_strictness,
                )
                manifest = build_draft_manifest(
                    plan=plan,
                    diff=diff,
                    installer_filename=installer_filename,
                    install_exe_name=install_exe_name,
                    silent_args=silent_args,
                )
                return plan, manifest, False

            # --- Wrapper fallback ---
            if not self._config.auto_wrap:
                raise TraceWorkerError(
                    f"Silent install failed and auto_wrap is disabled: {installer_error}"
                )

            logger.info("Engaging PSADT wrapper fallback")
            tracker.set_stage(STAGE_GENERATING_WRAPPER)

            candidates = list(detection_candidates or [])
            if not candidates and diff is not None and plan is not None:
                candidates = collect_detection_candidates(plan=plan, diff=diff)

            wrapper_gen = PsadtWrapperGenerator(
                self._config.psadt_wrapper_config
            )
            wrapper_dir = wrapper_gen.generate(
                installer_path=Path(host_installer_path),
                output_dir=Path(self._config.host_output_dir),
                product_name=product_name or installer_filename,
                installer_type=installer_type,
                detection_candidates=candidates,
            )

            tracker.set_stage(STAGE_VERIFYING_WRAPPER)
            verifier = WrapperVerifier(
                vmware=self._vmware,
                config=self._config.wrapper_verify_config,
            )
            vresult = verifier.verify(
                wrapper_dir=wrapper_dir,
                detection_candidates=candidates,
            )

            if not vresult.verified:
                raise TraceWorkerError(
                    f"PSADT wrapper verification failed: {vresult.summary()}"
                )

            logger.info("Wrapper verification passed: %s", vresult.summary())
            tracker.set_stage(STAGE_GENERATING_OUTPUT)

            if plan is None:
                plan = InstallPlan.from_diff(
                    install_command=f"Deploy-Application.ps1 (PSADT wrapper for {installer_filename})",
                    diff=diff if diff is not None else DiffResult(files=[], registry=[], services=[], scheduled_tasks=[]),
                )

            manifest = VerifiedTraceManifest(
                installer_filename=installer_filename,
                install_exe_name="Deploy-Application.ps1",
                silent_args=[],
                detection_candidates=candidates,
                verified=True,
                verification_errors=[],
                notes=[
                    "Installed via PSADT wrapper (GUI-mode); silent args not used.",
                    f"Wrapper verification: {vresult.summary()}",
                ],
                draft=False,
                verification_authority="psadt_wrapper_verified",
            )
            return plan, manifest, True

        except TraceWorkerError:
            raise
        except Exception as exc:
            raise TraceWorkerError(str(exc)) from exc
        finally:
            if self._config.pause_after_trace:
                logger.warning(
                    "Skipping snapshot revert (pause-after); VM left in post-trace state"
                )
            else:
                try:
                    logger.info("Reverting snapshot (cleanup)")
                    self._vmware.revert_snapshot()
                except VMwareControllerError:
                    logger.warning("Snapshot revert failed during cleanup")
