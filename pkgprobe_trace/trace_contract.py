"""Portable contract between OSS trace workers and api.pkgprobe.io verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

TRACE_CONTRACT_SCHEMA = "trace_contract_v1"
TRACE_CONTRACT_FILENAME = "trace_contract.json"


def write_trace_contract_file(
    host_output_dir: str,
    *,
    install_plan_dict: dict[str, Any],
    diff_dict: dict[str, Any],
    installer_filename: str,
    install_exe_name: str,
    silent_args: list[str],
    verification_strictness: str,
) -> Path:
    out = Path(host_output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / TRACE_CONTRACT_FILENAME
    payload = {
        "schema_version": TRACE_CONTRACT_SCHEMA,
        "installer_filename": installer_filename,
        "install_exe_name": install_exe_name,
        "silent_args": list(silent_args),
        "verification_strictness": verification_strictness,
        "install_plan": install_plan_dict,
        "diff": diff_dict,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path
