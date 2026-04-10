"""
Tests for exe.py: preflight promotion, uninstall candidates, and detection rules.
Uses mock preflight results; no real installer files required.
"""
from __future__ import annotations

import pytest

from pkgprobe.analyzers.exe import _promote_with_preflight
from pkgprobe.analyzers.exe_preflight import ExePreflightResult


# ── Preflight promotion ─────────────────────────────────────────────────


def test_promote_burn_from_preflight():
    pf = ExePreflightResult(burn_wix_suspected=True)
    it, conf, _fr = _promote_with_preflight("Unknown EXE installer", 0.3, pf)
    assert it == "WiX Burn"
    assert conf >= 0.55


def test_promote_squirrel_from_preflight():
    pf = ExePreflightResult(squirrel_suspected=True)
    it, conf, _fr = _promote_with_preflight("Unknown EXE installer", 0.3, pf)
    assert it == "Squirrel"
    assert conf >= 0.50


def test_no_promote_when_already_typed():
    pf = ExePreflightResult(burn_wix_suspected=True)
    it, conf, _fr = _promote_with_preflight("NSIS", 0.80, pf)
    assert it == "NSIS"
    assert conf == 0.80


def test_no_promote_without_hints():
    pf = ExePreflightResult()
    it, conf, _fr = _promote_with_preflight("Unknown EXE installer", 0.3, pf)
    assert it == "Unknown EXE installer"
    assert conf == 0.3


def test_promote_burn_beats_squirrel():
    pf = ExePreflightResult(burn_wix_suspected=True, squirrel_suspected=True)
    it, _conf, _fr = _promote_with_preflight("Unknown EXE installer", 0.3, pf)
    assert it == "WiX Burn"


# ── analyze_exe produces correct candidates per family ───────────────────
# These tests use a lightweight approach: call _promote then verify the
# branches in analyze_exe indirectly via a helper that builds plans from
# known installer_type strings.

from unittest.mock import patch, MagicMock
from pkgprobe.analyzers.exe import analyze_exe


def _make_plan(installer_type: str, conf: float = 0.70):
    """Build a plan by mocking out file I/O and detection, injecting installer_type."""
    pf = ExePreflightResult()
    with (
        patch("pkgprobe.analyzers.exe.Path") as MockPath,
        patch(
            "pkgprobe.analyzers.exe.detect_installer_type_full",
            return_value=(installer_type, conf, [], None),
        ),
        patch("pkgprobe.analyzers.exe.run_exe_preflight", return_value=pf),
        patch(
            "pkgprobe.analyzers.exe.assess_silent_viability_and_recommendation",
            return_value=("unknown", "silent_may_work"),
        ),
    ):
        mock_file = MagicMock()
        mock_file.read.return_value = b"MZ" + b"\x00" * 100
        MockPath.return_value.open.return_value.__enter__ = MagicMock(return_value=mock_file)
        MockPath.return_value.open.return_value.__exit__ = MagicMock(return_value=False)
        return analyze_exe("test.exe")


class TestUninstallCandidates:
    def test_inno_has_uninstall(self):
        plan = _make_plan("Inno Setup")
        assert len(plan.uninstall_candidates) >= 1
        assert "unins000" in plan.uninstall_candidates[0].command.lower()

    def test_nsis_has_uninstall(self):
        plan = _make_plan("NSIS")
        assert len(plan.uninstall_candidates) >= 1
        assert "uninstall.exe" in plan.uninstall_candidates[0].command.lower()

    def test_installshield_has_uninstall(self):
        plan = _make_plan("InstallShield")
        assert len(plan.uninstall_candidates) >= 1

    def test_burn_has_uninstall(self):
        plan = _make_plan("WiX Burn")
        assert len(plan.uninstall_candidates) >= 1
        assert "/uninstall" in plan.uninstall_candidates[0].command.lower()

    def test_squirrel_has_uninstall(self):
        plan = _make_plan("Squirrel")
        assert len(plan.uninstall_candidates) >= 1
        assert "update.exe" in plan.uninstall_candidates[0].command.lower()

    def test_msix_has_uninstall(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        assert len(plan.uninstall_candidates) >= 1
        assert "remove-appxpackage" in plan.uninstall_candidates[0].command.lower()


class TestDetectionRules:
    def test_all_families_have_arp_rule(self):
        for family in ("NSIS", "Inno Setup", "InstallShield", "WiX Burn", "Squirrel", "MSIX/AppX Wrapper", "Unknown EXE installer"):
            plan = _make_plan(family)
            arp_rules = [r for r in plan.detection_rules if r.kind == "registry_displayname"]
            assert len(arp_rules) >= 1, f"{family} missing ARP detection rule"

    def test_inno_has_file_exists_rule(self):
        plan = _make_plan("Inno Setup")
        rules = [r for r in plan.detection_rules if r.kind == "file_exists"]
        assert len(rules) >= 1
        assert "unins000" in rules[0].value.lower()

    def test_nsis_has_file_exists_rule(self):
        plan = _make_plan("NSIS")
        rules = [r for r in plan.detection_rules if r.kind == "file_exists"]
        assert len(rules) >= 1
        assert "uninstall.exe" in rules[0].value.lower()

    def test_burn_has_registry_key_rule(self):
        plan = _make_plan("WiX Burn")
        rules = [r for r in plan.detection_rules if r.kind == "registry_key"]
        assert len(rules) >= 1

    def test_squirrel_has_file_exists_rule(self):
        plan = _make_plan("Squirrel")
        rules = [r for r in plan.detection_rules if r.kind == "file_exists"]
        assert len(rules) >= 1

    def test_msix_has_powershell_rule(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        rules = [r for r in plan.detection_rules if r.kind == "powershell_check"]
        assert len(rules) >= 1

    def test_all_have_manual_followup(self):
        for family in ("NSIS", "Inno Setup", "InstallShield", "WiX Burn", "Squirrel", "MSIX/AppX Wrapper", "Unknown EXE installer"):
            plan = _make_plan(family)
            manual = [r for r in plan.detection_rules if r.kind == "manual_followup"]
            assert len(manual) >= 1, f"{family} missing manual_followup"


class TestInstallCandidates:
    def test_inno_has_candidates(self):
        plan = _make_plan("Inno Setup")
        assert len(plan.install_candidates) >= 2
        commands = " ".join(c.command for c in plan.install_candidates).lower()
        assert "/verysilent" in commands

    def test_nsis_has_candidates(self):
        plan = _make_plan("NSIS")
        assert len(plan.install_candidates) >= 1
        assert "/S" in plan.install_candidates[0].command

    def test_burn_has_candidates(self):
        plan = _make_plan("WiX Burn")
        assert len(plan.install_candidates) >= 1
        commands = " ".join(c.command for c in plan.install_candidates).lower()
        assert "/quiet" in commands

    def test_squirrel_has_candidates(self):
        plan = _make_plan("Squirrel")
        assert len(plan.install_candidates) >= 1

    def test_msix_has_candidates(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        assert len(plan.install_candidates) >= 1

    def test_unknown_has_generic_candidates(self):
        plan = _make_plan("Unknown EXE installer")
        assert len(plan.install_candidates) >= 2
        commands = " ".join(c.command for c in plan.install_candidates).lower()
        assert "/s" in commands or "/quiet" in commands


# ── Deployment assessment on plans ───────────────────────────────────────


class TestDeploymentAssessment:
    def test_all_families_have_deployment(self):
        for family in ("NSIS", "Inno Setup", "InstallShield", "WiX Burn", "Squirrel", "MSIX/AppX Wrapper", "Unknown EXE installer"):
            plan = _make_plan(family)
            assert plan.deployment is not None, f"{family} missing deployment"

    def test_burn_deployment_risk_high(self):
        plan = _make_plan("WiX Burn")
        assert plan.deployment is not None
        assert plan.deployment.deployment_risk == "high"
        assert plan.deployment.recommended_next_step == "trace_recommended"
        assert len(plan.deployment.risk_factors) >= 1

    def test_squirrel_deployment_risk_high(self):
        plan = _make_plan("Squirrel")
        assert plan.deployment is not None
        assert plan.deployment.deployment_risk == "high"
        assert plan.deployment.recommended_next_step == "trace_recommended"
        assert any("LOCALAPPDATA" in f or "per-user" in f.lower() for f in plan.deployment.risk_factors)

    def test_msix_deployment_alternate_path(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        assert plan.deployment is not None
        assert plan.deployment.recommended_next_step == "alternate_deployment_path"
        assert any("MSIX" in f or "AppxPackage" in f for f in plan.deployment.risk_factors)

    def test_unknown_deployment_manual_review(self):
        plan = _make_plan("Unknown EXE installer")
        assert plan.deployment is not None
        assert plan.deployment.deployment_risk == "high"
        assert plan.deployment.recommended_next_step == "manual_review"

    def test_installshield_deployment_moderate(self):
        plan = _make_plan("InstallShield")
        assert plan.deployment is not None
        assert plan.deployment.deployment_risk == "moderate"
        assert plan.deployment.recommended_next_step == "trace_recommended"


# ── Burn / Squirrel / MSIX specific notes ────────────────────────────────


class TestFamilySpecificNotes:
    def test_burn_has_caution_note(self):
        plan = _make_plan("WiX Burn")
        combined = " ".join(plan.notes).lower()
        assert "burn" in combined
        assert "chain" in combined or "payload" in combined

    def test_squirrel_has_deployment_note(self):
        plan = _make_plan("Squirrel")
        combined = " ".join(plan.notes).lower()
        assert "squirrel" in combined
        assert "localappdata" in combined or "per-user" in combined

    def test_msix_has_deployment_note(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        combined = " ".join(plan.notes).lower()
        assert "msix" in combined or "appx" in combined
        assert "add-appxpackage" in combined or "native" in combined


# ── FamilyResult on plans (when verdict is available) ────────────────────


from pkgprobe.models import FamilyResult, Evidence


def _make_plan_with_family_result(installer_type: str, conf: float = 0.75):
    """Build a plan with a FamilyResult populated from signatures."""
    pf = ExePreflightResult()
    family_result = FamilyResult(
        family=installer_type.lower().replace(" ", "_"),
        confidence=conf,
        confidence_tier="high" if conf >= 0.75 else "medium" if conf >= 0.55 else "low",
        evidence=[Evidence(kind="strong", detail="marker: test_marker")],
        alternatives_considered=[],
    )
    with (
        patch("pkgprobe.analyzers.exe.Path") as MockPath,
        patch(
            "pkgprobe.analyzers.exe.detect_installer_type_full",
            return_value=(installer_type, conf, [], family_result),
        ),
        patch("pkgprobe.analyzers.exe.run_exe_preflight", return_value=pf),
        patch(
            "pkgprobe.analyzers.exe.assess_silent_viability_and_recommendation",
            return_value=("unknown", "silent_may_work"),
        ),
    ):
        mock_file = MagicMock()
        mock_file.read.return_value = b"MZ" + b"\x00" * 100
        MockPath.return_value.open.return_value.__enter__ = MagicMock(return_value=mock_file)
        MockPath.return_value.open.return_value.__exit__ = MagicMock(return_value=False)
        return analyze_exe("test.exe")


class TestFamilyResultOnPlan:
    def test_family_result_present(self):
        plan = _make_plan_with_family_result("NSIS")
        assert plan.family_result is not None
        assert plan.family_result.confidence >= 0.75
        assert plan.family_result.confidence_tier == "high"

    def test_family_result_evidence_populated(self):
        plan = _make_plan_with_family_result("Inno Setup")
        assert plan.family_result is not None
        assert len(plan.family_result.evidence) >= 1

    def test_family_result_none_without_detection(self):
        plan = _make_plan("Unknown EXE installer")
        # family_result is None when detect_installer_type_full returns None
        assert plan.family_result is None


# ── Packaging tier per family ─────────────────────────────────────────────


class TestPackagingTier:
    def test_nsis_high_confidence_is_simple(self):
        plan = _make_plan_with_family_result("NSIS", conf=0.85)
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "simple"

    def test_inno_high_confidence_is_simple(self):
        plan = _make_plan_with_family_result("Inno Setup", conf=0.85)
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "simple"

    def test_nsis_low_confidence_is_pro(self):
        plan = _make_plan("NSIS", conf=0.45)
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "pro"

    def test_installshield_is_pro(self):
        plan = _make_plan("InstallShield")
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "pro"

    def test_msix_is_pro(self):
        plan = _make_plan("MSIX/AppX Wrapper")
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "pro"

    def test_burn_is_auto_wrap(self):
        plan = _make_plan("WiX Burn")
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "auto_wrap"

    def test_squirrel_is_auto_wrap(self):
        plan = _make_plan("Squirrel")
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "auto_wrap"

    def test_unknown_is_auto_wrap(self):
        plan = _make_plan("Unknown EXE installer")
        assert plan.deployment is not None
        assert plan.deployment.packaging_tier == "auto_wrap"

    def test_tier_reason_populated(self):
        plan = _make_plan("InstallShield")
        assert plan.deployment is not None
        assert plan.deployment.tier_reason != ""

    def test_suggested_command_populated(self):
        plan = _make_plan("NSIS")
        assert plan.deployment is not None
        assert plan.deployment.suggested_command != ""
        assert "/S" in plan.deployment.suggested_command


# ── MSI packaging tier ────────────────────────────────────────────────────


class TestMsiPackagingTier:
    def test_msi_with_product_code_is_simple(self):
        from unittest.mock import patch
        with patch("pkgprobe.analyzers.msi._msi_module_available", return_value=True), \
             patch("pkgprobe.analyzers.msi._read_msi_properties", return_value=(
                 {"ProductName": "Test", "ProductCode": "{GUID}", "UpgradeCode": None, "ProductVersion": "1.0", "Manufacturer": "Test"},
                 False,
             )), \
             patch("pkgprobe.analyzers.msi._file_size_str", return_value="1024"):
            from pkgprobe.analyzers.msi import analyze_msi
            plan = analyze_msi("test.msi")
            assert plan.deployment is not None
            assert plan.deployment.packaging_tier == "simple"
            assert plan.deployment.deployment_risk == "low"

    def test_msi_without_product_code_is_pro(self):
        from unittest.mock import patch
        with patch("pkgprobe.analyzers.msi._msi_module_available", return_value=True), \
             patch("pkgprobe.analyzers.msi._read_msi_properties", return_value=(
                 {"ProductName": "Test", "ProductCode": None, "UpgradeCode": None, "ProductVersion": "1.0", "Manufacturer": "Test"},
                 False,
             )), \
             patch("pkgprobe.analyzers.msi._file_size_str", return_value="1024"):
            from pkgprobe.analyzers.msi import analyze_msi
            plan = analyze_msi("test.msi")
            assert plan.deployment is not None
            assert plan.deployment.packaging_tier == "pro"
            assert plan.deployment.deployment_risk == "moderate"

    def test_msi_suggested_command_populated(self):
        from unittest.mock import patch
        with patch("pkgprobe.analyzers.msi._msi_module_available", return_value=True), \
             patch("pkgprobe.analyzers.msi._read_msi_properties", return_value=(
                 {"ProductName": "Test", "ProductCode": "{GUID}", "UpgradeCode": None, "ProductVersion": "1.0", "Manufacturer": "Test"},
                 False,
             )), \
             patch("pkgprobe.analyzers.msi._file_size_str", return_value="1024"):
            from pkgprobe.analyzers.msi import analyze_msi
            plan = analyze_msi("test.msi")
            assert plan.deployment is not None
            assert "msiexec" in plan.deployment.suggested_command
