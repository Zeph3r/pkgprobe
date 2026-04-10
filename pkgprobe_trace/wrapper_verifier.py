"""
Verify a PSADT wrapper by deploying it in a clean VM snapshot.

Checks:
  1. Wrapper exit code (0 or 3010 = acceptable)
  2. Detection rules from the manifest (registry, file, service, etc.)

This module requires a running VMware Workstation instance
(uses VMwareController for all guest operations).
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .verified_manifest import DetectionCandidate
from .vmware_controller import VMwareController, VMwareControllerError

logger = logging.getLogger(__name__)

_ACCEPTABLE_EXIT_CODES = {0, 3010, 1641}

_GUEST_WRAPPER_DIR = r"C:\trace\psadt_wrapper"
_GUEST_DETECT_PS1 = r"C:\trace\psadt_wrapper\detect.ps1"
_GUEST_EXIT_CODE_FILE = r"C:\trace\wrapper_exit_code.txt"
_GUEST_DETECT_SCRIPT_DIR = r"C:\trace\detect_checks"


class WrapperVerifierError(RuntimeError):
    pass


@dataclass(frozen=True)
class WrapperVerifierConfig:
    guest_tools_timeout_sec: int = 120
    guest_tools_poll_sec: float = 2.0
    boot_wait_sec: int = 5
    wrapper_run_timeout_sec: int = 600
    detection_check_timeout_sec: int = 60
    tail_wait_sec: int = 30
    min_confidence_for_check: float = 0.5
    critical_confidence: float = 0.9
    required_pass_confidence: float = 0.7


@dataclass
class DetectionCheckResult:
    candidate_type: str
    candidate_value: str
    confidence: float
    passed: bool
    detail: str = ""


@dataclass
class WrapperVerificationResult:
    exit_code: int
    exit_code_acceptable: bool
    detection_results: List[DetectionCheckResult] = field(default_factory=list)
    verified: bool = False
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        status = "VERIFIED" if self.verified else "FAILED"
        passed = sum(1 for d in self.detection_results if d.passed)
        total = len(self.detection_results)
        parts = [
            f"Wrapper verification: {status}",
            f"Exit code: {self.exit_code} ({'acceptable' if self.exit_code_acceptable else 'BAD'})",
            f"Detection rules: {passed}/{total} passed",
        ]
        if self.errors:
            parts.append(f"Errors: {'; '.join(self.errors)}")
        return " | ".join(parts)


class WrapperVerifier:
    """Deploy a PSADT wrapper in a clean VM and verify installation success."""

    def __init__(
        self,
        *,
        vmware: VMwareController,
        config: WrapperVerifierConfig | None = None,
    ) -> None:
        self._vmware = vmware
        self._config = config or WrapperVerifierConfig()

    def verify(
        self,
        *,
        wrapper_dir: Path,
        detection_candidates: List[DetectionCandidate],
    ) -> WrapperVerificationResult:
        wrapper_dir = Path(wrapper_dir)
        if not wrapper_dir.is_dir():
            raise WrapperVerifierError(
                f"Wrapper directory not found: {wrapper_dir}"
            )

        result = WrapperVerificationResult(exit_code=-1, exit_code_acceptable=False)

        try:
            self._prepare_vm()
            self._upload_wrapper(wrapper_dir)
            exit_code = self._run_wrapper()
            result.exit_code = exit_code
            result.exit_code_acceptable = exit_code in _ACCEPTABLE_EXIT_CODES

            if not result.exit_code_acceptable:
                result.errors.append(
                    f"Wrapper exited with code {exit_code} (expected 0 or 3010)"
                )
                return result

            result.detection_results = self._run_detection_checks(
                detection_candidates
            )
            result.verified = self._evaluate_verification(result)

        except VMwareControllerError as exc:
            result.errors.append(f"VM operation failed: {exc}")
            logger.exception("Wrapper verification VM error")
        except Exception as exc:
            result.errors.append(f"Unexpected error: {exc}")
            logger.exception("Wrapper verification error")
        finally:
            self._cleanup_vm()

        return result

    def _prepare_vm(self) -> None:
        logger.info("Reverting VM to clean snapshot for wrapper verification")
        self._vmware.revert_snapshot()

        logger.info("Starting VM")
        self._vmware.start_vm(nogui=True)

        logger.info("Waiting for VMware Tools")
        self._vmware.wait_for_guest_tools(
            poll_interval_sec=self._config.guest_tools_poll_sec,
            timeout_sec=self._config.guest_tools_timeout_sec,
        )

        if self._config.boot_wait_sec > 0:
            logger.info("Boot settle wait: %ss", self._config.boot_wait_sec)
            time.sleep(self._config.boot_wait_sec)

    def _upload_wrapper(self, wrapper_dir: Path) -> None:
        self._vmware.run_program_in_guest(
            r"C:\Windows\System32\cmd.exe",
            ["/c", f"mkdir {_GUEST_WRAPPER_DIR}"],
            check=False,
            timeout_sec=30,
        )

        for item in wrapper_dir.rglob("*"):
            if not item.is_file():
                continue
            rel = item.relative_to(wrapper_dir)
            guest_path = f"{_GUEST_WRAPPER_DIR}\\{str(rel)}"
            guest_parent = str(Path(guest_path).parent)
            self._vmware.run_program_in_guest(
                r"C:\Windows\System32\cmd.exe",
                ["/c", f'if not exist "{guest_parent}" mkdir "{guest_parent}"'],
                check=False,
                timeout_sec=30,
            )
            self._vmware.copy_file_to_guest(
                str(item), guest_path, timeout_sec=120
            )

        logger.info("Wrapper uploaded to guest: %s", _GUEST_WRAPPER_DIR)

    def _run_wrapper(self) -> int:
        logger.info("Running PSADT wrapper in guest")

        ps_cmd = (
            f'-ExecutionPolicy Bypass -File "{_GUEST_WRAPPER_DIR}\\Deploy-Application.ps1" '
            f"-DeploymentType Install -DeployMode Interactive; "
            f"$LASTEXITCODE | Out-File -FilePath '{_GUEST_EXIT_CODE_FILE}' -Encoding ascii"
        )

        self._vmware.run_program_in_guest(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            [ps_cmd],
            interactive=True,
            timeout_sec=self._config.wrapper_run_timeout_sec,
        )

        if self._config.tail_wait_sec > 0:
            logger.info("Waiting %ss for tail processes", self._config.tail_wait_sec)
            time.sleep(self._config.tail_wait_sec)

        exit_code = self._read_guest_exit_code()
        logger.info("Wrapper exit code: %s", exit_code)
        return exit_code

    def _read_guest_exit_code(self) -> int:
        """Read exit code from the file written by the wrapper run."""
        try:
            import tempfile
            tmp = os.path.join(tempfile.gettempdir(), "wrapper_exit_code.txt")
            self._vmware.copy_file_from_guest(_GUEST_EXIT_CODE_FILE, tmp)
            with open(tmp, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            os.unlink(tmp)
            return int(raw)
        except (VMwareControllerError, ValueError, OSError) as exc:
            logger.warning("Could not read wrapper exit code: %s", exc)
            return -1

    def _run_detection_checks(
        self, candidates: List[DetectionCandidate]
    ) -> List[DetectionCheckResult]:
        results: List[DetectionCheckResult] = []
        eligible = [
            c for c in candidates
            if float(c.confidence) >= self._config.min_confidence_for_check
        ]

        if not eligible:
            logger.warning("No detection candidates above confidence threshold")
            return results

        for c in eligible:
            script = self._detection_script(c)
            if not script:
                continue

            passed = self._run_inline_ps1(script)
            results.append(
                DetectionCheckResult(
                    candidate_type=c.type,
                    candidate_value=c.value,
                    confidence=float(c.confidence),
                    passed=passed,
                    detail=f"{'PASS' if passed else 'FAIL'}: {c.type} = {c.value}",
                )
            )
            logger.info(
                "Detection check %s: %s = %s -> %s",
                c.type,
                c.value,
                "PASS" if passed else "FAIL",
                c.confidence,
            )

        return results

    @staticmethod
    def _detection_script(c: DetectionCandidate) -> str | None:
        if c.type in ("registry_key", "msi_product_code"):
            path = c.value.replace("HKLM\\", "HKLM:\\").replace("HKCU\\", "HKCU:\\")
            return f'if (Test-Path "{path}") {{ exit 0 }} else {{ exit 1 }}'
        if c.type == "file_exists":
            return f'if (Test-Path "{c.value}") {{ exit 0 }} else {{ exit 1 }}'
        if c.type == "service_exists":
            return (
                f'$s = Get-Service -Name "{c.value}" -ErrorAction SilentlyContinue; '
                "if ($null -ne $s) { exit 0 } else { exit 1 }"
            )
        if c.type == "scheduled_task_exists":
            return (
                f'$t = Get-ScheduledTask -TaskName "{c.value}" -ErrorAction SilentlyContinue; '
                "if ($null -ne $t) { exit 0 } else { exit 1 }"
            )
        return None

    def _run_inline_ps1(self, script: str) -> bool:
        """Run a small PowerShell script in the guest. Return True if exit code 0."""
        try:
            proc = self._vmware.run_program_in_guest(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ["-ExecutionPolicy", "Bypass", "-Command", script],
                timeout_sec=self._config.detection_check_timeout_sec,
                check=False,
            )
            return proc.returncode == 0
        except VMwareControllerError as exc:
            logger.warning("Detection script failed: %s", exc)
            return False

    def _evaluate_verification(
        self, result: WrapperVerificationResult
    ) -> bool:
        if not result.exit_code_acceptable:
            return False

        if not result.detection_results:
            result.errors.append(
                "No detection checks ran; cannot verify installation"
            )
            return False

        has_high_pass = any(
            d.passed and d.confidence >= self._config.required_pass_confidence
            for d in result.detection_results
        )
        if not has_high_pass:
            result.errors.append(
                f"No detection candidate with confidence >= {self._config.required_pass_confidence} passed"
            )
            return False

        critical_failures = [
            d for d in result.detection_results
            if not d.passed and d.confidence >= self._config.critical_confidence
        ]
        if critical_failures:
            names = ", ".join(f"{d.candidate_type}={d.candidate_value}" for d in critical_failures)
            result.errors.append(
                f"Critical detection candidates failed: {names}"
            )
            return False

        return True

    def _cleanup_vm(self) -> None:
        try:
            logger.info("Reverting snapshot (verification cleanup)")
            self._vmware.revert_snapshot()
        except VMwareControllerError:
            logger.warning("Snapshot revert failed during verification cleanup")
