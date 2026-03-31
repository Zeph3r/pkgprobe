from __future__ import annotations

from pkgprobe_trace.diff_engine import (
    DiffEngine,
    DiffResult,
    FileChange,
    RegistryChange,
    subtract_baseline_diff,
)


def test_subtract_baseline_removes_matching_paths() -> None:
    install = DiffResult(
        files=[
            FileChange(path=r"C:\Program Files\App\a.exe", change_type="create"),
            FileChange(path=r"C:\Program Files\App\b.dll", change_type="create"),
        ],
        registry=[
            RegistryChange(path=r"HKLM\SOFTWARE\Vendor\Key", change_type="set_value"),
        ],
    )
    baseline = DiffResult(
        files=[
            FileChange(path=r"C:\Program Files\App\a.exe", change_type="create"),
        ],
        registry=[],
    )
    out = subtract_baseline_diff(install, baseline)
    assert len(out.files) == 1
    assert out.files[0].path == r"C:\Program Files\App\b.dll"
    assert len(out.registry) == 1


def test_pid_filter_keeps_installer_process_tree(tmp_path) -> None:
    csv_path = tmp_path / "trace.csv"
    csv_path.write_text(
        "Operation,Path,Process Name,PID,Parent PID\n"
        r'CreateFile,C:\Program Files\App\keep.exe,installer.exe,100,50' "\n"
        r'CreateFile,C:\Child\also.exe,child.exe,200,100' "\n"
        r'CreateFile,C:\Other\nope.txt,other.exe,300,999' "\n",
        encoding="utf-8",
    )
    eng = DiffEngine(installer_process_image="installer.exe")
    d = eng.build_diff_from_procmon_csv(str(csv_path))
    paths = {f.path for f in d.files}
    assert r"C:\Program Files\App\keep.exe" in paths
    assert r"C:\Child\also.exe" in paths
    assert r"C:\Other\nope.txt" not in paths
