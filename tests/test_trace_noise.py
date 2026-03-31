from __future__ import annotations

from pkgprobe_trace.trace_noise import should_skip_file_event, should_skip_registry_event


def test_skips_vmware_program_files() -> None:
    assert should_skip_file_event(
        "installer.exe",
        r"C:\Program Files\VMware\VMware Tools\glib-2.0.dll",
    )


def test_skips_procmon_process() -> None:
    assert should_skip_file_event(
        "procmon64.exe",
        r"C:\Program Files\7-Zip\7z.exe",
    )


def test_keeps_installer_program_files() -> None:
    assert not should_skip_file_event(
        "installer.exe",
        r"C:\Program Files\7-Zip\7z.exe",
    )


def test_skips_trace_tools_path() -> None:
    assert should_skip_file_event(
        "installer.exe",
        r"C:\trace\tools\foo.dll",
    )


def test_skips_vmware_registry() -> None:
    assert should_skip_registry_event(
        "installer.exe",
        r"HKLM\SOFTWARE\VMware, Inc.\VMware Tools",
    )


def test_keeps_uninstall_registry() -> None:
    assert not should_skip_registry_event(
        "installer.exe",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
    )
