"""Tests for pkgprobe_trace.psadt_wrapper."""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from pkgprobe_trace.psadt_wrapper import (
    PsadtWrapperConfig,
    PsadtWrapperError,
    PsadtWrapperGenerator,
    _render_detect_ps1,
)
from pkgprobe_trace.verified_manifest import DetectionCandidate


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    return tmp_path / "output"


@pytest.fixture
def fake_installer(tmp_path: Path) -> Path:
    p = tmp_path / "setup.exe"
    p.write_bytes(b"MZ" + b"\x00" * 100)
    return p


class TestPsadtWrapperGenerator:
    def test_generate_creates_expected_structure(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
            product_name="TestApp",
            installer_type="NSIS",
        )

        assert wrapper.is_dir()
        assert (wrapper / "Deploy-Application.ps1").is_file()
        assert (wrapper / "detect.ps1").is_file()
        assert (wrapper / "Files" / "setup.exe").is_file()
        assert (wrapper / "AppDeployToolkit").is_dir()
        assert (wrapper / "AppDeployToolkit" / "AppDeployToolkit.ps1").is_file()
        assert (wrapper / "AppDeployToolkit" / "AppDeployToolkitMain.ps1").is_file()
        assert (wrapper / "AppDeployToolkit" / "AppDeployToolkitConfig.xml").is_file()

    def test_installer_bytes_copied(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
        )
        staged = wrapper / "Files" / "setup.exe"
        assert staged.read_bytes() == fake_installer.read_bytes()

    def test_deploy_ps1_contains_installer_name(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
            product_name="AcmePro",
            installer_type="Inno Setup",
        )
        content = (wrapper / "Deploy-Application.ps1").read_text(encoding="utf-8")
        assert "setup.exe" in content
        assert "AcmePro" in content
        assert "Inno Setup" in content

    def test_deploy_ps1_close_apps(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
            close_apps=["notepad", "chrome"],
        )
        content = (wrapper / "Deploy-Application.ps1").read_text(encoding="utf-8")
        assert "notepad,chrome" in content
        assert "Show-InstallationWelcome" in content

    def test_deploy_ps1_no_close_apps(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
        )
        content = (wrapper / "Deploy-Application.ps1").read_text(encoding="utf-8")
        assert "No conflicting apps to close" in content

    def test_reboot_passthrough_disabled(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator(PsadtWrapperConfig(allow_reboot_passthrough=False))
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
        )
        content = (wrapper / "Deploy-Application.ps1").read_text(encoding="utf-8")
        assert "suppressing for Intune" in content

    def test_reboot_passthrough_enabled(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator(PsadtWrapperConfig(allow_reboot_passthrough=True))
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
        )
        content = (wrapper / "Deploy-Application.ps1").read_text(encoding="utf-8")
        assert "Exit-Script -ExitCode $result" in content
        assert "suppressing" not in content

    def test_custom_toolkit_path(self, tmp_path: Path, fake_installer: Path) -> None:
        custom_toolkit = tmp_path / "my_psadt"
        custom_toolkit.mkdir()
        (custom_toolkit / "AppDeployToolkit.ps1").write_text("# custom", encoding="utf-8")
        (custom_toolkit / "AppDeployToolkitMain.ps1").write_text("# custom main", encoding="utf-8")

        gen = PsadtWrapperGenerator(
            PsadtWrapperConfig(psadt_toolkit_path=str(custom_toolkit))
        )
        output = tmp_path / "out"
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=output,
        )
        content = (wrapper / "AppDeployToolkit" / "AppDeployToolkit.ps1").read_text(encoding="utf-8")
        assert content == "# custom"

    def test_missing_custom_toolkit_raises(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator(
            PsadtWrapperConfig(psadt_toolkit_path="/nonexistent/path")
        )
        with pytest.raises(PsadtWrapperError, match="not found"):
            gen.generate(
                installer_path=fake_installer,
                output_dir=tmp_output,
            )

    def test_missing_installer_raises(self, tmp_output: Path) -> None:
        gen = PsadtWrapperGenerator()
        with pytest.raises(PsadtWrapperError, match="not found"):
            gen.generate(
                installer_path=Path("/nonexistent/setup.exe"),
                output_dir=tmp_output,
            )

    def test_serviceui_copied(
        self, tmp_path: Path, fake_installer: Path
    ) -> None:
        sui = tmp_path / "ServiceUI.exe"
        sui.write_bytes(b"\x00" * 50)

        gen = PsadtWrapperGenerator(
            PsadtWrapperConfig(serviceui_path=str(sui))
        )
        output = tmp_path / "out"
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=output,
        )
        assert (wrapper / "ServiceUI.exe").is_file()


class TestDetectPs1:
    def test_registry_key(self) -> None:
        candidates = [
            DetectionCandidate(
                type="registry_key",
                value=r"HKLM\SOFTWARE\AcmeCorp\TestApp",
                confidence=0.9,
            )
        ]
        script = _render_detect_ps1(candidates)
        assert "HKLM:\\" in script
        assert "Test-Path" in script
        assert "exit 0" in script

    def test_file_exists(self) -> None:
        candidates = [
            DetectionCandidate(
                type="file_exists",
                value=r"C:\Program Files\Acme\app.exe",
                confidence=0.8,
            )
        ]
        script = _render_detect_ps1(candidates)
        assert "Test-Path" in script
        assert r"C:\Program Files\Acme\app.exe" in script

    def test_service_exists(self) -> None:
        candidates = [
            DetectionCandidate(
                type="service_exists",
                value="AcmeService",
                confidence=0.7,
            )
        ]
        script = _render_detect_ps1(candidates)
        assert "Get-Service" in script
        assert "AcmeService" in script

    def test_scheduled_task(self) -> None:
        candidates = [
            DetectionCandidate(
                type="scheduled_task_exists",
                value="AcmeUpdater",
                confidence=0.6,
            )
        ]
        script = _render_detect_ps1(candidates)
        assert "Get-ScheduledTask" in script
        assert "AcmeUpdater" in script

    def test_picks_highest_confidence(self) -> None:
        candidates = [
            DetectionCandidate(type="file_exists", value="low.exe", confidence=0.3),
            DetectionCandidate(type="registry_key", value=r"HKLM\Best", confidence=0.95),
            DetectionCandidate(type="file_exists", value="mid.exe", confidence=0.6),
        ]
        script = _render_detect_ps1(candidates)
        assert "HKLM:\\" in script
        assert "Best" in script

    def test_no_candidates(self) -> None:
        script = _render_detect_ps1([])
        assert script.strip() == "exit 1"

    def test_detection_with_detection_candidates(
        self, tmp_output: Path, fake_installer: Path
    ) -> None:
        gen = PsadtWrapperGenerator()
        candidates = [
            DetectionCandidate(
                type="registry_key",
                value=r"HKLM\SOFTWARE\TestApp",
                confidence=0.9,
            )
        ]
        wrapper = gen.generate(
            installer_path=fake_installer,
            output_dir=tmp_output,
            detection_candidates=candidates,
        )
        detect_content = (wrapper / "detect.ps1").read_text(encoding="utf-8")
        assert "Test-Path" in detect_content
        assert "TestApp" in detect_content
