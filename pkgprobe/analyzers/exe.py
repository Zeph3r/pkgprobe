from __future__ import annotations

import os
from pathlib import Path

from pkgprobe.models import CommandCandidate, DetectionRule, Evidence, InstallPlan
from pkgprobe.analyzers.signatures import detect_installer_type


def analyze_exe(exe_path: str) -> InstallPlan:
    path = Path(exe_path)
    with path.open("rb") as f:
        data = f.read()

    installer_type, conf, hits = detect_installer_type(path, data)

    plan = InstallPlan(
        input_path=exe_path,
        file_type="exe",
        installer_type=installer_type,
        confidence=conf,
        metadata={
            "FileName": os.path.basename(exe_path),
            "SizeBytes": len(data),
        },
    )

    # Add evidence
    for h in hits:
        plan.notes.append(f"Hit: {h.name} ({h.confidence:.2f}) - {h.evidence}")

    # Silent candidates by type (heuristic)
    it = installer_type.lower()

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

    elif "installshield" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" /s /v"/qn /norestart"',
                confidence=0.70,
                evidence=[Evidence(kind="signature", detail="InstallShield common quiet pattern")],
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

    elif "squirrel" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command=f'"{exe_path}" --silent',
                confidence=0.45,
                evidence=[Evidence(kind="signature", detail="Squirrel varies; low confidence")],
            )
        )
        plan.notes.append("Squirrel installers vary a lot; you often need app-specific flags or Update.exe behaviors.")

    elif "msix" in it or "appx" in it:
        plan.install_candidates.append(
            CommandCandidate(
                command="Add-AppxPackage <path-to-msix-or-appx>",
                confidence=0.35,
                evidence=[Evidence(kind="hint", detail="Detected AppX/MSIX strings but input is EXE")],
            )
        )
        plan.notes.append("Input is EXE but contains MSIX/AppX hints. It may be a wrapper/bootstrapper.")

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
        plan.notes.append("Unknown installer type; silent switches are guesses. Add more signatures to improve.")

    # Minimal detection guess (weak): suggest checking ARP via DisplayName in trace mode later
    plan.detection_rules.append(
        DetectionRule(
            kind="manual_followup",
            value="Consider adding trace-install later to generate real detection (files/registry/services).",
            confidence=0.20,
            evidence=[Evidence(kind="note", detail="MVP does not execute installers")],
        )
    )

    return plan
