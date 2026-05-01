from __future__ import annotations

import json
from pathlib import Path

from pkgprobe_trace.trace_contract import (
    TRACE_CONTRACT_FILENAME,
    write_trace_contract_file,
)


def test_write_trace_contract_includes_wrapper_discovered_candidates(tmp_path: Path) -> None:
    out = write_trace_contract_file(
        str(tmp_path),
        install_plan_dict={"install_command": "Deploy-Application.ps1 -DeployMode Silent"},
        diff_dict={"files": [], "registry": [], "services": [], "scheduled_tasks": []},
        installer_filename="vlc-3.0.23-win64.exe",
        install_exe_name="Deploy-Application.ps1",
        silent_args=["/S"],
        verification_strictness="balanced",
        wrapper_discovered_candidates=[
            {
                "type": "registry_key",
                "value": r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VLC media player",
                "confidence": 0.9,
                "rationale": "New uninstall key found after wrapper install",
            }
        ],
    )
    assert out == tmp_path / TRACE_CONTRACT_FILENAME
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "trace_contract_v1"
    assert payload["silent_args"] == ["/S"]
    assert len(payload["wrapper_discovered_candidates"]) == 1
    assert payload["wrapper_discovered_candidates"][0]["type"] == "registry_key"
