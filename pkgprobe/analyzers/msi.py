from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from pkgprobe.models import CommandCandidate, DetectionRule, Evidence, InstallPlan

# Keys we read from MSI Property table when _msi is available
_MSI_PROPERTY_KEYS = ("ProductName", "ProductCode", "UpgradeCode", "ProductVersion", "Manufacturer")


def _file_size_str(msi_path: str) -> Optional[str]:
    """Return file size as string, or None if unreadable."""
    try:
        return str(os.path.getsize(msi_path)) if os.path.exists(msi_path) else None
    except OSError:
        return None


def _msi_module_available() -> bool:
    """True if Python's _msi module can be imported (CPython on Windows)."""
    try:
        import _msi  # type: ignore  # noqa: F401
        return True
    except Exception:
        return False


def _read_msi_properties(msi_path: str) -> Tuple[Dict[str, Optional[str]], bool]:
    """
    Read MSI Property table via _msi. Call only when _msi_module_available() is True.
    Returns (dict of property name -> value, read_failed).
    read_failed is True if OpenDatabase or any view raised an exception.
    """
    import _msi  # type: ignore

    result: Dict[str, Optional[str]] = {k: None for k in _MSI_PROPERTY_KEYS}
    read_failed = False

    if not os.path.exists(msi_path):
        return result, True

    try:
        db = _msi.OpenDatabase(msi_path, _msi.MSIDBOPEN_READONLY)
    except Exception:
        return result, True

    for prop in _MSI_PROPERTY_KEYS:
        try:
            view = db.OpenView(f"SELECT `Value` FROM `Property` WHERE `Property`='{prop}'")
            view.Execute(None)
            rec = view.Fetch()
            view.Close()
            if rec is not None:
                result[prop] = rec.GetString(1)
        except Exception:
            read_failed = True
            result[prop] = None

    return result, read_failed


def analyze_msi(msi_path: str) -> InstallPlan:
    msi_module_available = _msi_module_available()

    if not msi_module_available:
        meta: Dict[str, Optional[str]] = {
            "FileName": os.path.basename(msi_path),
            "SizeBytes": _file_size_str(msi_path),
        }
        product_code = None
        product_name = None
        upgrade_code = None
        product_version = None
        manufacturer = None
        read_failed = False
    else:
        props, read_failed = _read_msi_properties(msi_path)
        product_code = props.get("ProductCode")
        product_name = props.get("ProductName")
        upgrade_code = props.get("UpgradeCode")
        product_version = props.get("ProductVersion")
        manufacturer = props.get("Manufacturer")
        meta = {
            "ProductName": product_name,
            "ProductCode": product_code,
            "UpgradeCode": upgrade_code,
            "ProductVersion": product_version,
            "Manufacturer": manufacturer,
            "FileName": os.path.basename(msi_path),
            "SizeBytes": _file_size_str(msi_path),
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
        plan.uninstall_candidates.append(
            CommandCandidate(
                command=f'msiexec /x "{msi_path}" /qn /norestart',
                confidence=0.40,
                evidence=[Evidence(kind="msi", detail="Fallback uninstall by package path (less reliable)")],
            )
        )

    # Notes: precise wording by state (no misleading "ProductCode not found" when _msi was never used)
    if not msi_module_available:
        plan.notes.append("MSI properties unavailable (Python _msi module not loaded).")
        plan.notes.append("Use CPython on Windows (not WSL) for full MSI metadata.")
    elif read_failed:
        plan.notes.append("MSI property read failed.")
    elif not product_code:
        plan.notes.append("ProductCode not found in MSI Property table.")

    return plan
