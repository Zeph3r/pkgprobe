from __future__ import annotations

from pkgprobe_trace.diff_engine import DiffResult, RegistryChange
from pkgprobe_trace.installplan_generator import InstallPlan
from pkgprobe_trace.manifest_builder import build_verified_manifest


def test_msi_product_code_candidate_for_guid_uninstall_key() -> None:
    guid = "{11111111-1111-1111-1111-111111111111}"
    path = rf"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{guid}\DisplayName"
    diff = DiffResult(
        registry=[RegistryChange(path=path, change_type="set_value")],
    )
    plan = InstallPlan.from_diff(install_command="setup.exe /S", diff=diff)
    m = build_verified_manifest(
        plan=plan,
        diff=diff,
        installer_filename="setup.exe",
        install_exe_name="setup.exe",
        silent_args=["/S"],
    )
    msi = [c for c in m.detection_candidates if c.type == "msi_product_code"]
    assert msi
    assert guid in msi[0].value
