from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from pkgprobe.models import CommandCandidate, DetectionRule, Evidence, InstallPlan


def _read_msi_property(msi_path: str, prop: str) -> Optional[str]:
    """
    Read an MSI property from the Property table via Windows-only _msi module.
    """
    try:
        import _msi  # type: ignore
    except Exception:
        return None

    if not os.path.exists(msi_path):
        return None

    try:
        db = _msi.OpenDatabase(msi_path, _msi.MSIDBOPEN_READONLY)
        view = db.OpenView(f"SELECT `Value` FROM `Property` WHERE `Property`='{prop}'")
        view.Execute(None)
        rec = view.Fetch()
        view.Close()
        if rec is None:
            return None
        return rec.GetString(1)
    except Exception:
        return None


def analyze_msi(msi_path: str) -> InstallPlan:
    product_code = _read_msi_property(msi_path, "ProductCode")
    upgrade_code = _read_msi_property(msi_path, "UpgradeCode")
    product_version = _read_msi_property(msi_path, "ProductVersion")
    manufacturer = _read_msi_property(msi_path, "Manufacturer")
    product_name = _read_msi_property(msi_path, "ProductName")

    meta: Dict[str, Optional[str]] = {
        "ProductName": product_name,
        "ProductCode": product_code,
        "UpgradeCode": upgrade_code,
        "ProductVersion": product_version,
        "Manufacturer": manufacturer,
    }

    confidence = 0.95 if product_code else 0.75

    plan = InstallPlan(
        input_path=msi_path,
        file_type="msi",
        installer_type="MSI",
        confidence=confidence,
        metadata=meta,
    )

    # Install command
    plan.install_candidates.append(
        CommandCandidate(
            command=f'msiexec /i "{msi_path}" /qn /norestart',
            confidence=0.95,
            evidence=[Evidence(kind="msi", detail="Standard msiexec silent install")],
        )
    )

    # Uninstall command (prefer ProductCode)
    if product_code:
        plan.uninstall_candidates.append(
            CommandCandidate(
                command=f"msiexec /x {product_code} /qn /norestart",
                confidence=0.95,
                evidence=[Evidence(kind="msi", detail="ProductCode found in Property table")],
            )
        )
        plan.detection_rules.append(
            DetectionRule(
                kind="msi_product_code",
                value=product_code,
                confidence=0.95,
                evidence=[Evidence(kind="msi", detail="ProductCode suggests reliable MSI detection")],
            )
        )
    else:
        plan.notes.append("ProductCode not found (MSI may be unusual or property read failed).")
        plan.uninstall_candidates.append(
            CommandCandidate(
                command=f'msiexec /x "{msi_path}" /qn /norestart',
                confidence=0.40,
                evidence=[Evidence(kind="msi", detail="Fallback uninstall by package path (less reliable)")],
            )
        )

    # Extra helpful note if _msi isn't available
    try:
        import _msi  # type: ignore # noqa: F401
    except Exception:
        plan.notes.append("Python _msi module unavailable. Use CPython on Windows (not WSL) to read MSI properties.")

    return plan
