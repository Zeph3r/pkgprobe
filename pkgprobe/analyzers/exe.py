from __future__ import annotations

import os
from pathlib import Path

from pkgprobe.models import (
    CommandCandidate,
    DeploymentAssessment,
    DetectionRule,
    Evidence,
    InstallPlan,
)
from pkgprobe.analyzers.exe_preflight import (
    ExePreflightResult,
    assess_deployment,
    assess_silent_viability_and_recommendation,
    run_exe_preflight,
)
from pkgprobe.analyzers.signatures import detect_installer_type_full


def _promote_with_preflight(
    installer_type: str,
    conf: float,
    preflight: ExePreflightResult,
    family_result=None,
) -> tuple[str, float, object]:
    """
    When byte-level detection returned Unknown but preflight found structural
    evidence (7z listing), promote installer_type so the correct candidate
    branch fires.  Returns updated (installer_type, conf, family_result).
    """
    if installer_type != "Unknown EXE installer":
        return installer_type, conf, family_result
    if preflight.burn_wix_suspected:
        new_conf = max(conf, 0.55)
        if family_result is not None:
            from pkgprobe.models import FamilyResult
            family_result = FamilyResult(
                family="burn",
                confidence=new_conf,
                confidence_tier="medium",
                evidence=[
                    Evidence(kind="structural", detail="marker: preflight_7z_wixburn_hint"),
                    *(family_result.evidence if family_result else []),
                ],
                alternatives_considered=family_result.alternatives_considered if family_result else [],
            )
        return "WiX Burn", new_conf, family_result
    if preflight.squirrel_suspected:
        new_conf = max(conf, 0.50)
        if family_result is not None:
            from pkgprobe.models import FamilyResult
            family_result = FamilyResult(
                family="squirrel",
                confidence=new_conf,
                confidence_tier="low",
                evidence=[
                    Evidence(kind="structural", detail="marker: preflight_7z_squirrel_hint"),
                    *(family_result.evidence if family_result else []),
                ],
                alternatives_considered=family_result.alternatives_considered if family_result else [],
            )
        return "Squirrel", new_conf, family_result
    return installer_type, conf, family_result


def analyze_exe(exe_path: str) -> InstallPlan:
    path = Path(exe_path)
    with path.open("rb") as f:
        data = f.read()

    installer_type, conf, hits, family_result = detect_installer_type_full(path, data)

    preflight = run_exe_preflight(exe_path)

    installer_type, conf, family_result = _promote_with_preflight(
        installer_type, conf, preflight, family_result,
    )

    sv, rec = assess_silent_viability_and_recommendation(
        installer_type=installer_type,
        confidence=conf,
        preflight=preflight,
    )

    confidence_tier = family_result.confidence_tier if family_result else "low"
    deploy_dict = assess_deployment(
        installer_type=installer_type,
        confidence=conf,
        preflight=preflight,
        confidence_tier=confidence_tier,
    )
    deployment = DeploymentAssessment(**deploy_dict)

    plan = InstallPlan(
        input_path=exe_path,
        file_type="exe",
        installer_type=installer_type,
        confidence=conf,
        metadata={
            "FileName": os.path.basename(exe_path),
            "SizeBytes": len(data),
            "preflight": preflight.to_json_dict(),
        },
        family_result=family_result,
        silent_viability=sv,
        recommendation=rec,
        deployment=deployment,
    )

    for h in hits:
        plan.notes.append(f"Hit: {h.name} ({h.confidence:.2f}) - {h.evidence}")

    it = installer_type.lower()

    # ── Install + uninstall candidates by family ─────────────────────────

    if "inno" in it:
        plan.install_candidates.extend([
            CommandCandidate(
                command=f'"{exe_path}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-',
                confidence=0.88,
                evidence=[Evidence(kind="signature", detail="Inno Setup common flags")],
            ),
            CommandCandidate(
                command=f'"{exe_path}" /SILENT /SUPPRESSMSGBOXES /NORESTART /SP-',
                confidence=0.62,
                evidence=[Evidence(kind="signature", detail="Inno Setup alternate silent flags")],
            ),
        ])
        plan.uninstall_candidates.append(
            CommandCandidate(
                command="unins000.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-",
                confidence=0.55,
                evidence=[Evidence(kind="signature", detail="Inno Setup typical uninstaller name")],
            )
        )

    elif "nsis" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" /S',
                confidence=0.85,
                evidence=[Evidence(kind="signature", detail="NSIS commonly supports /S")],
            )
        )
        plan.uninstall_candidates.append(
            CommandCandidate(
                command='"<install_dir>\\uninstall.exe" /S',
                confidence=0.50,
                evidence=[Evidence(kind="signature", detail="NSIS convention: uninstall.exe with /S")],
            )
        )

    elif "installshield" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" /s /v"/qn /norestart"',
                confidence=0.70,
                evidence=[Evidence(kind="signature", detail="InstallShield common quiet pattern")],
            )
        )
        plan.uninstall_candidates.append(
            CommandCandidate(
                command='"<install_dir>\\setup.exe" /s /uninst',
                confidence=0.40,
                evidence=[Evidence(kind="signature", detail="InstallShield uninstall via setup.exe; verify with ARP UninstallString")],
            )
        )

    elif "burn" in it or "bootstrapper" in it:
        plan.install_candidates.extend([
            CommandCandidate(
                command=f'"{exe_path}" /quiet /norestart',
                confidence=0.78,
                evidence=[Evidence(kind="signature", detail="Burn bundles often support /quiet")],
            ),
            CommandCandidate(
                command=f'"{exe_path}" /passive /norestart',
                confidence=0.55,
                evidence=[Evidence(kind="signature", detail="Burn bundles sometimes support /passive")],
            ),
        ])
        plan.uninstall_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" /uninstall /quiet /norestart',
                confidence=0.65,
                evidence=[Evidence(kind="signature", detail="Burn bundles support /uninstall flag")],
            )
        )
        plan.notes.append(
            "Burn bootstrapper detected. Burn bundles can chain multiple "
            "MSI/EXE payloads and install prerequisites. /quiet may not "
            "suppress all chained UI. Trace validation strongly recommended."
        )

    elif "squirrel" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" --silent',
                confidence=0.45,
                evidence=[Evidence(kind="signature", detail="Squirrel varies; low confidence")],
            )
        )
        plan.uninstall_candidates.append(
            CommandCandidate(
                command='Update.exe --uninstall',
                confidence=0.50,
                evidence=[Evidence(kind="signature", detail="Squirrel convention: Update.exe --uninstall")],
            )
        )
        plan.notes.append(
            "Squirrel installers vary widely. Typically per-user to "
            "%LOCALAPPDATA% with Update.exe lifecycle. Silent install may "
            "'work' but produce a poor packaging citizen for mass deployment."
        )

    elif "msix" in it or "appx" in it:
        if conf >= 0.75:
            plan.install_candidates.append(
                CommandCandidate(
                    command="Add-AppxPackage -Path <extracted-msix-or-appx>",
                    confidence=0.60,
                    evidence=[Evidence(kind="signature", detail="Strong MSIX/AppX evidence; prefer native deployment")],
                )
            )
            plan.install_candidates.append(
                CommandCandidate(
                    command=f'"{exe_path}" /quiet',
                    confidence=0.30,
                    evidence=[Evidence(kind="hint", detail="EXE wrapper fallback; native MSIX preferred")],
                )
            )
        else:
            plan.install_candidates.append(
                CommandCandidate(
                    command="Add-AppxPackage <path-to-msix-or-appx>",
                    confidence=0.35,
                    evidence=[Evidence(kind="hint", detail="Detected AppX/MSIX strings but input is EXE")],
                )
            )
        plan.uninstall_candidates.append(
            CommandCandidate(
                command="Remove-AppxPackage <PackageFullName>",
                confidence=0.35,
                evidence=[Evidence(kind="hint", detail="PowerShell removal for AppX/MSIX packages")],
            )
        )
        plan.notes.append(
            "Input is EXE but contains MSIX/AppX evidence. "
            "Consider native MSIX deployment via Add-AppxPackage "
            "rather than EXE wrapper packaging."
        )

    else:
        plan.install_candidates.extend([
            CommandCandidate(
                command=f'"{exe_path}" /S',
                confidence=0.25,
                evidence=[Evidence(kind="fallback", detail="Generic guess (/S) - very unreliable")],
            ),
            CommandCandidate(
                command=f'"{exe_path}" /quiet /norestart',
                confidence=0.25,
                evidence=[Evidence(kind="fallback", detail="Generic guess (/quiet) - very unreliable")],
            ),
        ])
        plan.notes.append("Unknown installer type; silent switches are guesses. Use trace-install for real detection.")

    if plan.install_candidates and plan.deployment:
        plan.deployment.suggested_command = plan.install_candidates[0].command

    # ── Detection rules (family-aware) ───────────────────────────────────

    plan.detection_rules.append(
        DetectionRule(
            kind="registry_displayname",
            value=r"Check HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall for DisplayName matching the product",
            confidence=0.40,
            evidence=[Evidence(kind="heuristic", detail="Standard ARP detection; works for most installer types")],
        )
    )

    if "inno" in it:
        plan.detection_rules.append(
            DetectionRule(
                kind="file_exists",
                value="unins000.exe in the application install directory",
                confidence=0.50,
                evidence=[Evidence(kind="signature", detail="Inno Setup always drops unins000.exe")],
            )
        )
    elif "nsis" in it:
        plan.detection_rules.append(
            DetectionRule(
                kind="file_exists",
                value="uninstall.exe in the application install directory",
                confidence=0.45,
                evidence=[Evidence(kind="signature", detail="NSIS commonly creates uninstall.exe")],
            )
        )
    elif "burn" in it:
        plan.detection_rules.append(
            DetectionRule(
                kind="registry_key",
                value=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BundleUpgradeCode}",
                confidence=0.55,
                evidence=[Evidence(kind="signature", detail="Burn bundles register via BundleUpgradeCode GUID")],
            )
        )
    elif "squirrel" in it:
        plan.detection_rules.append(
            DetectionRule(
                kind="file_exists",
                value=r"Update.exe and app-*.exe in %LOCALAPPDATA%\<app>",
                confidence=0.50,
                evidence=[Evidence(kind="signature", detail="Squirrel installs to per-user LocalAppData with Update.exe")],
            )
        )
    elif "msix" in it or "appx" in it:
        rule_conf = 0.60 if conf >= 0.75 else 0.45
        plan.detection_rules.append(
            DetectionRule(
                kind="powershell_check",
                value="Get-AppxPackage -Name <PackageFamilyName>",
                confidence=rule_conf,
                evidence=[Evidence(kind="hint", detail="AppX/MSIX packages are enumerable via PowerShell")],
            )
        )

    plan.detection_rules.append(
        DetectionRule(
            kind="manual_followup",
            value="Consider adding trace-install later to generate real detection (files/registry/services).",
            confidence=0.20,
            evidence=[Evidence(kind="note", detail="Static analysis does not execute installers")],
        )
    )

    from pkgprobe.analyzers.telemetry import get_telemetry
    tel = get_telemetry()
    if tel.enabled:
        tel.record(
            "exe_analysis_complete",
            installer_type=installer_type,
            confidence=conf,
            confidence_tier=confidence_tier,
            deployment_risk=deployment.deployment_risk,
            recommended_next_step=deployment.recommended_next_step,
            preflight_promotion=preflight.burn_wix_suspected or preflight.squirrel_suspected,
            install_candidate_count=len(plan.install_candidates),
        )

    return plan
