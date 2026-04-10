"""Tests for version-aware detection and upgrade orchestration."""
from __future__ import annotations

from pkgprobe.models import DetectionRule, Evidence
from pkgprobe_trace.diff_engine import DiffResult, RegistryChange
from pkgprobe_trace.installplan_generator import InstallPlan
from pkgprobe_trace.intunewin_packager import IntuneWinPackager, _wow6432_sibling
from pkgprobe_trace.manifest_builder import build_draft_manifest, collect_detection_candidates
from pkgprobe_trace.verified_manifest import DetectionCandidate, VerifiedTraceManifest


# ---------------------------------------------------------------------------
# Model serialization
# ---------------------------------------------------------------------------


class TestDetectionRuleVersion:
    def test_version_fields_default_none(self) -> None:
        rule = DetectionRule(kind="msi_product_code", value="{CODE}", confidence=0.95)
        assert rule.version is None
        assert rule.version_operator is None

    def test_version_fields_roundtrip_json(self) -> None:
        rule = DetectionRule(
            kind="msi_product_code",
            value="{CODE}",
            confidence=0.95,
            version="1.2.3",
            version_operator="ge",
        )
        data = rule.model_dump()
        restored = DetectionRule(**data)
        assert restored.version == "1.2.3"
        assert restored.version_operator == "ge"


class TestDetectionCandidateVersion:
    def test_version_fields_default_empty(self) -> None:
        c = DetectionCandidate(type="msi_product_code", value="path")
        assert c.version == ""
        assert c.version_operator == ""

    def test_version_fields_set(self) -> None:
        c = DetectionCandidate(
            type="msi_product_code", value="path",
            version="2.0.0", version_operator="ge",
        )
        assert c.version == "2.0.0"
        assert c.version_operator == "ge"


class TestVerifiedTraceManifestVersion:
    def test_product_fields_default_empty(self) -> None:
        m = VerifiedTraceManifest()
        assert m.product_version == ""
        assert m.product_code == ""

    def test_product_fields_roundtrip_json(self) -> None:
        m = VerifiedTraceManifest(
            product_version="3.1.0",
            product_code="{ABCDEF00-0000-0000-0000-000000000000}",
        )
        raw = m.to_json()
        restored = VerifiedTraceManifest.from_json(raw)
        assert restored.product_version == "3.1.0"
        assert restored.product_code == "{ABCDEF00-0000-0000-0000-000000000000}"

    def test_from_json_missing_product_fields(self) -> None:
        """Old manifests without product_version/product_code still deserialize."""
        raw = '{"schema_version":"v1","installer_filename":"x.msi"}'
        m = VerifiedTraceManifest.from_json(raw)
        assert m.product_version == ""
        assert m.product_code == ""


# ---------------------------------------------------------------------------
# Manifest builder
# ---------------------------------------------------------------------------


class TestManifestBuilderVersion:
    def _make_diff_with_guid(self, guid: str) -> DiffResult:
        return DiffResult(
            registry=[
                RegistryChange(
                    path=rf"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{guid}\DisplayName",
                    change_type="set_value",
                ),
            ],
        )

    def test_collect_candidates_attaches_version(self) -> None:
        guid = "{22222222-2222-2222-2222-222222222222}"
        diff = self._make_diff_with_guid(guid)
        plan = InstallPlan.from_diff(install_command="setup.exe /S", diff=diff)
        cands = collect_detection_candidates(plan=plan, diff=diff, product_version="5.0.0")
        msi = [c for c in cands if c.type == "msi_product_code"]
        assert msi
        assert msi[0].version == "5.0.0"
        assert msi[0].version_operator == "ge"

    def test_collect_candidates_no_version_when_empty(self) -> None:
        guid = "{33333333-3333-3333-3333-333333333333}"
        diff = self._make_diff_with_guid(guid)
        plan = InstallPlan.from_diff(install_command="setup.exe /S", diff=diff)
        cands = collect_detection_candidates(plan=plan, diff=diff, product_version="")
        msi = [c for c in cands if c.type == "msi_product_code"]
        assert msi
        assert msi[0].version == ""

    def test_build_draft_manifest_passes_product_fields(self) -> None:
        guid = "{44444444-4444-4444-4444-444444444444}"
        diff = self._make_diff_with_guid(guid)
        plan = InstallPlan.from_diff(install_command="setup.exe /S", diff=diff)
        manifest = build_draft_manifest(
            plan=plan, diff=diff,
            installer_filename="app.msi",
            install_exe_name="app.msi",
            product_version="1.0.0",
            product_code=guid,
        )
        assert manifest.product_version == "1.0.0"
        assert manifest.product_code == guid


# ---------------------------------------------------------------------------
# WOW6432Node sibling helper
# ---------------------------------------------------------------------------


class TestWow6432Sibling:
    def test_generates_wow_path(self) -> None:
        path = r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}"
        result = _wow6432_sibling(path)
        assert "WOW6432Node" in result
        assert result.endswith("{GUID}")

    def test_skips_if_already_wow(self) -> None:
        path = r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}"
        assert _wow6432_sibling(path) == ""

    def test_returns_empty_for_unrecognized(self) -> None:
        assert _wow6432_sibling(r"HKCU:\SOFTWARE\Something") == ""


# ---------------------------------------------------------------------------
# detect.ps1 rendering
# ---------------------------------------------------------------------------


class TestRenderDetectPs1:
    def test_version_aware_msi_detection(self) -> None:
        candidates = [
            DetectionCandidate(
                type="msi_product_code",
                value=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{AAAA}",
                confidence=0.95,
                version="2.5.0",
                version_operator="ge",
            ),
        ]
        script = IntuneWinPackager._render_detect_ps1(candidates)
        assert "[version]" in script
        assert '"2.5.0"' in script
        assert "-ge" in script
        assert "WOW6432Node" in script
        assert "DisplayVersion" in script
        assert "exit 0" in script
        assert "exit 1" in script

    def test_version_eq_operator(self) -> None:
        candidates = [
            DetectionCandidate(
                type="msi_product_code",
                value=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BBBB}",
                confidence=0.95,
                version="3.0.0",
                version_operator="eq",
            ),
        ]
        script = IntuneWinPackager._render_detect_ps1(candidates)
        assert "-eq" in script
        assert '"3.0.0"' in script

    def test_no_version_falls_back_to_test_path(self) -> None:
        candidates = [
            DetectionCandidate(
                type="msi_product_code",
                value=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{CCCC}",
                confidence=0.95,
            ),
        ]
        script = IntuneWinPackager._render_detect_ps1(candidates)
        assert "Test-Path" in script
        assert "[version]" not in script

    def test_file_exists_unchanged(self) -> None:
        candidates = [
            DetectionCandidate(type="file_exists", value=r"C:\Program Files\App\app.exe", confidence=0.8),
        ]
        script = IntuneWinPackager._render_detect_ps1(candidates)
        assert "Test-Path" in script

    def test_empty_candidates(self) -> None:
        assert IntuneWinPackager._render_detect_ps1([]) == "exit 1\n"


# ---------------------------------------------------------------------------
# install.ps1 rendering
# ---------------------------------------------------------------------------


class TestRenderInstallPs1:
    def test_simple_install_without_product_code(self) -> None:
        script = IntuneWinPackager._render_install_ps1("app.msi", ["/qn", "/norestart"])
        assert "app.msi" in script
        assert "Start-Process" in script
        assert "3010" in script
        assert "msiexec" not in script.lower() or "msiexec" not in script.split("$installer")[0]

    def test_uninstall_before_install_with_product_code(self) -> None:
        code = "{DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD}"
        script = IntuneWinPackager._render_install_ps1(
            "app.msi", ["/qn", "/norestart"],
            product_code=code,
        )
        assert code in script
        assert "msiexec" in script.lower()
        assert "/x" in script
        assert "WOW6432Node" in script
        assert "Removing existing version" in script
        assert "3010" in script

    def test_3010_treated_as_success(self) -> None:
        script = IntuneWinPackager._render_install_ps1("app.msi", ["/qn"])
        assert "if ($exitCode -eq 3010) { $exitCode = 0 }" in script

    def test_no_product_code_no_uninstall_block(self) -> None:
        script = IntuneWinPackager._render_install_ps1("app.exe", ["/S"])
        assert "msiexec" not in script.lower()
        assert "productCode" not in script
