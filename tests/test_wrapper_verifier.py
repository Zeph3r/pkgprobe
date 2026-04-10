"""Tests for pkgprobe_trace.wrapper_verifier."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from pkgprobe_trace.verified_manifest import DetectionCandidate
from pkgprobe_trace.vmware_controller import VMwareController, VMwareControllerError
from pkgprobe_trace.wrapper_verifier import (
    WrapperVerifier,
    WrapperVerifierConfig,
    WrapperVerifierError,
    WrapperVerificationResult,
    _ACCEPTABLE_EXIT_CODES,
)


@pytest.fixture
def mock_vmware() -> MagicMock:
    vm = MagicMock(spec=VMwareController)
    vm.revert_snapshot = MagicMock()
    vm.start_vm = MagicMock()
    vm.wait_for_guest_tools = MagicMock()
    vm.copy_file_to_guest = MagicMock()
    vm.copy_file_from_guest = MagicMock()
    vm.run_program_in_guest = MagicMock(
        return_value=MagicMock(returncode=0, stdout="", stderr="")
    )
    return vm


@pytest.fixture
def wrapper_dir(tmp_path: Path) -> Path:
    d = tmp_path / "psadt_wrapper"
    d.mkdir()
    (d / "Deploy-Application.ps1").write_text("# wrapper", encoding="utf-8")
    (d / "detect.ps1").write_text("exit 0", encoding="utf-8")
    files = d / "Files"
    files.mkdir()
    (files / "setup.exe").write_bytes(b"MZ" + b"\x00" * 50)
    toolkit = d / "AppDeployToolkit"
    toolkit.mkdir()
    (toolkit / "AppDeployToolkit.ps1").write_text("# toolkit", encoding="utf-8")
    return d


@pytest.fixture
def candidates() -> list[DetectionCandidate]:
    return [
        DetectionCandidate(
            type="registry_key",
            value=r"HKLM\SOFTWARE\TestApp",
            confidence=0.9,
            rationale="ARP entry",
        ),
        DetectionCandidate(
            type="file_exists",
            value=r"C:\Program Files\TestApp\app.exe",
            confidence=0.75,
            rationale="Main binary",
        ),
    ]


class TestWrapperVerifier:
    def test_verification_passes_when_all_checks_pass(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
        candidates: list[DetectionCandidate],
        tmp_path: Path,
    ) -> None:
        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("0", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest
        mock_vmware.run_program_in_guest.return_value = MagicMock(returncode=0)

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.exit_code == 0
        assert result.exit_code_acceptable is True
        assert result.verified is True
        assert len(result.detection_results) == 2
        assert all(d.passed for d in result.detection_results)
        assert len(result.errors) == 0

    def test_verification_fails_on_bad_exit_code(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
        candidates: list[DetectionCandidate],
    ) -> None:
        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("1603", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.exit_code == 1603
        assert result.exit_code_acceptable is False
        assert result.verified is False
        assert any("1603" in e for e in result.errors)

    def test_exit_code_3010_is_acceptable(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
        candidates: list[DetectionCandidate],
    ) -> None:
        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("3010", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest
        mock_vmware.run_program_in_guest.return_value = MagicMock(returncode=0)

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.exit_code == 3010
        assert result.exit_code_acceptable is True
        assert result.verified is True

    def test_verification_fails_when_critical_detection_fails(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
    ) -> None:
        candidates = [
            DetectionCandidate(
                type="registry_key",
                value=r"HKLM\SOFTWARE\CriticalApp",
                confidence=0.95,
            ),
        ]

        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("0", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest
        mock_vmware.run_program_in_guest.return_value = MagicMock(returncode=1)

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.exit_code == 0
        assert result.exit_code_acceptable is True
        assert result.verified is False
        assert any("Critical" in e or "confidence" in e for e in result.errors)

    def test_verification_fails_with_no_high_confidence_pass(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
    ) -> None:
        candidates = [
            DetectionCandidate(
                type="file_exists",
                value=r"C:\something.txt",
                confidence=0.5,
            ),
        ]

        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("0", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest
        mock_vmware.run_program_in_guest.return_value = MagicMock(returncode=0)

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.exit_code_acceptable is True
        assert result.verified is False
        assert any("confidence" in e for e in result.errors)

    def test_vm_error_is_caught(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
        candidates: list[DetectionCandidate],
    ) -> None:
        mock_vmware.revert_snapshot.side_effect = VMwareControllerError("VM crashed")

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        result = verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        assert result.verified is False
        assert any("VM operation failed" in e for e in result.errors)

    def test_missing_wrapper_dir_raises(
        self,
        mock_vmware: MagicMock,
        candidates: list[DetectionCandidate],
    ) -> None:
        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)

        with pytest.raises(WrapperVerifierError, match="not found"):
            verifier.verify(
                wrapper_dir=Path("/nonexistent"),
                detection_candidates=candidates,
            )

    def test_snapshot_reverted_on_cleanup(
        self,
        mock_vmware: MagicMock,
        wrapper_dir: Path,
        candidates: list[DetectionCandidate],
    ) -> None:
        def fake_copy_from_guest(guest_path: str, host_path: str, **kw):
            if "exit_code" in guest_path:
                Path(host_path).write_text("0", encoding="utf-8")

        mock_vmware.copy_file_from_guest.side_effect = fake_copy_from_guest
        mock_vmware.run_program_in_guest.return_value = MagicMock(returncode=0)

        config = WrapperVerifierConfig(boot_wait_sec=0, tail_wait_sec=0)
        verifier = WrapperVerifier(vmware=mock_vmware, config=config)
        verifier.verify(
            wrapper_dir=wrapper_dir,
            detection_candidates=candidates,
        )

        revert_calls = mock_vmware.revert_snapshot.call_count
        assert revert_calls >= 2  # Once for prepare, once for cleanup

    def test_detection_script_generation(self) -> None:
        c = DetectionCandidate(type="registry_key", value=r"HKLM\SOFTWARE\Test", confidence=0.9)
        script = WrapperVerifier._detection_script(c)
        assert script is not None
        assert "HKLM:\\" in script
        assert "Test-Path" in script

        c2 = DetectionCandidate(type="file_exists", value=r"C:\app.exe", confidence=0.8)
        script2 = WrapperVerifier._detection_script(c2)
        assert script2 is not None
        assert "Test-Path" in script2

        c3 = DetectionCandidate(type="service_exists", value="MySvc", confidence=0.7)
        script3 = WrapperVerifier._detection_script(c3)
        assert script3 is not None
        assert "Get-Service" in script3

        c4 = DetectionCandidate(type="scheduled_task_exists", value="MyTask", confidence=0.6)
        script4 = WrapperVerifier._detection_script(c4)
        assert script4 is not None
        assert "Get-ScheduledTask" in script4

    def test_summary_format(self) -> None:
        result = WrapperVerificationResult(
            exit_code=0,
            exit_code_acceptable=True,
            verified=True,
        )
        s = result.summary()
        assert "VERIFIED" in s
        assert "0" in s

        result2 = WrapperVerificationResult(
            exit_code=1603,
            exit_code_acceptable=False,
            verified=False,
            errors=["Bad exit code"],
        )
        s2 = result2.summary()
        assert "FAILED" in s2
        assert "1603" in s2


class TestAcceptableExitCodes:
    def test_acceptable_set(self) -> None:
        assert 0 in _ACCEPTABLE_EXIT_CODES
        assert 3010 in _ACCEPTABLE_EXIT_CODES
        assert 1641 in _ACCEPTABLE_EXIT_CODES
        assert 1603 not in _ACCEPTABLE_EXIT_CODES
        assert -1 not in _ACCEPTABLE_EXIT_CODES
