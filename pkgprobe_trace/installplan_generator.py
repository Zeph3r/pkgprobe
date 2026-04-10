"""
InstallPlan generation.

InstallPlan is the stable artifact produced by tracing an installer.
It is designed to be JSON-serializable and easy to consume by other pkgprobe
components (CLI, backend services, policy engines).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List

from .diff_engine import DiffResult, FileChange


@dataclass(frozen=True)
class InstallPlan:
    install_command: str
    files_created: List[FileChange]
    files_modified: List[FileChange]
    files_deleted: List[FileChange]
    registry_keys: list
    services: list
    scheduled_tasks: list

    @classmethod
    def from_diff(cls, *, install_command: str, diff: DiffResult) -> "InstallPlan":
        files_created = [f for f in diff.files if f.change_type == "create"]
        files_modified = [f for f in diff.files if f.change_type == "modify"]
        files_deleted = [f for f in diff.files if f.change_type == "delete"]
        return cls(
            install_command=install_command,
            files_created=files_created,
            files_modified=files_modified,
            files_deleted=files_deleted,
            registry_keys=[asdict(x) for x in diff.registry],
            services=[asdict(x) for x in diff.services],
            scheduled_tasks=[asdict(x) for x in diff.scheduled_tasks],
        )

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "install_command": self.install_command,
            "files_created": [asdict(x) for x in self.files_created],
            "files_modified": [asdict(x) for x in self.files_modified],
            "files_deleted": [asdict(x) for x in self.files_deleted],
            "registry_keys": self.registry_keys,
            "services": self.services,
            "scheduled_tasks": self.scheduled_tasks,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json_dict(cls, d: Dict[str, Any]) -> "InstallPlan":
        def _fcs(key: str) -> List[FileChange]:
            raw = d.get(key) or []
            if not isinstance(raw, list):
                return []
            return [FileChange(**x) for x in raw]  # type: ignore[arg-type]

        return cls(
            install_command=str(d.get("install_command") or ""),
            files_created=_fcs("files_created"),
            files_modified=_fcs("files_modified"),
            files_deleted=_fcs("files_deleted"),
            registry_keys=list(d.get("registry_keys") or []),
            services=list(d.get("services") or []),
            scheduled_tasks=list(d.get("scheduled_tasks") or []),
        )

