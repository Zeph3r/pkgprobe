from __future__ import annotations

from pkgprobe_trace.diff_engine import DiffResult, RegistryChange
from pkgprobe_trace.installplan_generator import InstallPlan
from pkgprobe_trace.manifest_builder import collect_detection_candidates


def test_msi_product_code_candidate_for_guid_uninstall_key() -> None:
    guid = "{11111111-1111-1111-1111-111111111111}"
    path = rf"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{guid}\DisplayName"
    diff = DiffResult(
        registry=[RegistryChange(path=path, change_type="set_value")],
    )
    plan = InstallPlan.from_diff(install_command="setup.exe /S", diff=diff)
    cands = collect_detection_candidates(plan=plan, diff=diff)
    msi = [c for c in cands if c.type == "msi_product_code"]
    assert msi
    assert guid in msi[0].value
