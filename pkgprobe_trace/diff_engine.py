"""
Diff engine: parse trace artifacts into a structured change summary.

First implementation: parse ProcMon CSV exported from a PML.
This is intentionally heuristic and deterministic (pure function of CSV input).

Future extension points:
- Replace CSV parsing with direct PML parsing if you add a PML reader.
- Merge with an active "baseline snapshot" diff (filesystem/registry pre/post).
"""

from __future__ import annotations

import csv
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Literal, Optional

logger = logging.getLogger(__name__)

FileChangeType = Literal["create", "modify", "delete"]
RegistryChangeType = Literal["create_key", "set_value", "delete_key", "delete_value"]


@dataclass(frozen=True)
class FileChange:
    path: str
    change_type: FileChangeType
    process: Optional[str] = None


@dataclass(frozen=True)
class RegistryChange:
    path: str
    change_type: RegistryChangeType
    process: Optional[str] = None


@dataclass(frozen=True)
class ServiceChange:
    name: str
    binary_path: Optional[str] = None
    display_name: Optional[str] = None


@dataclass(frozen=True)
class ScheduledTaskChange:
    name: str
    action: Optional[str] = None


@dataclass
class DiffResult:
    files: List[FileChange] = field(default_factory=list)
    registry: List[RegistryChange] = field(default_factory=list)
    services: List[ServiceChange] = field(default_factory=list)
    scheduled_tasks: List[ScheduledTaskChange] = field(default_factory=list)

    def to_json_dict(self) -> Dict[str, object]:
        return {
            "files": [asdict(x) for x in self.files],
            "registry": [asdict(x) for x in self.registry],
            "services": [asdict(x) for x in self.services],
            "scheduled_tasks": [asdict(x) for x in self.scheduled_tasks],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_json_dict(), indent=2, sort_keys=True)


class DiffEngine:
    """
    Convert ProcMon CSV events into a coarse-grained diff.

    CSV expectations:
    - Has header row.
    - Includes `Operation` and `Path` columns (ProcMon standard export).
    - `Process Name` is used when available.
    """

    FILE_CREATE_OPS = {"CreateFile", "CopyFile"}
    FILE_MODIFY_OPS = {"WriteFile", "SetEndOfFileInformationFile"}
    FILE_DELETE_OPS = {"DeleteFile", "SetDispositionInformationFile"}

    REG_CREATE_OPS = {"RegCreateKey", "RegCreateKeyEx"}
    REG_SET_OPS = {"RegSetValue", "RegSetValueEx"}
    REG_DELETE_KEY_OPS = {"RegDeleteKey", "RegDeleteKeyEx"}
    REG_DELETE_VALUE_OPS = {"RegDeleteValue"}

    def build_diff_from_procmon_csv(self, csv_path: str) -> DiffResult:
        return self.build_diff_from_procmon_csvs([csv_path])

    def build_diff_from_procmon_csvs(self, csv_paths: Iterable[str]) -> DiffResult:
        file_changes: Dict[str, FileChange] = {}
        reg_changes: List[RegistryChange] = []

        for csv_path in csv_paths:
            if not os.path.isfile(csv_path):
                logger.warning("Missing ProcMon CSV: %s", csv_path)
                continue

            logger.info("Parsing ProcMon CSV: %s", csv_path)
            with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    op = (row.get("Operation") or "").strip()
                    path = (row.get("Path") or "").strip()
                    process = (row.get("Process Name") or row.get("ProcessName") or "").strip() or None

                    if not op or not path:
                        continue

                    if op in self.FILE_CREATE_OPS:
                        self._record_file_change(file_changes, path, "create", process)
                        continue
                    if op in self.FILE_MODIFY_OPS:
                        self._record_file_change(file_changes, path, "modify", process)
                        continue
                    if op in self.FILE_DELETE_OPS:
                        self._record_file_change(file_changes, path, "delete", process)
                        continue

                    if op in self.REG_CREATE_OPS:
                        reg_changes.append(RegistryChange(path=path, change_type="create_key", process=process))
                        continue
                    if op in self.REG_SET_OPS:
                        reg_changes.append(RegistryChange(path=path, change_type="set_value", process=process))
                        continue
                    if op in self.REG_DELETE_KEY_OPS:
                        reg_changes.append(RegistryChange(path=path, change_type="delete_key", process=process))
                        continue
                    if op in self.REG_DELETE_VALUE_OPS:
                        reg_changes.append(RegistryChange(path=path, change_type="delete_value", process=process))
                        continue

        files = sorted(file_changes.values(), key=lambda x: x.path.lower())
        services = self._infer_services_from_registry(reg_changes)
        tasks = self._infer_scheduled_tasks(reg_changes)

        return DiffResult(files=files, registry=reg_changes, services=services, scheduled_tasks=tasks)

    @staticmethod
    def _record_file_change(
        existing: Dict[str, FileChange],
        path: str,
        change_type: FileChangeType,
        process: Optional[str],
    ) -> None:
        prev = existing.get(path)
        if prev is None:
            existing[path] = FileChange(path=path, change_type=change_type, process=process)
            return

        precedence = {"delete": 3, "create": 2, "modify": 1}
        if precedence[change_type] >= precedence[prev.change_type]:
            existing[path] = FileChange(path=path, change_type=change_type, process=process)

    @staticmethod
    def _infer_services_from_registry(reg_changes: List[RegistryChange]) -> List[ServiceChange]:
        # Heuristic: any registry activity under CurrentControlSet\Services suggests a service.
        services: Dict[str, ServiceChange] = {}
        for rc in reg_changes:
            marker = "\\Services\\"
            if marker not in rc.path:
                continue
            after = rc.path.split(marker, 1)[1]
            name = after.split("\\", 1)[0].strip()
            if not name:
                continue
            services.setdefault(name, ServiceChange(name=name))
        return sorted(services.values(), key=lambda s: s.name.lower())

    @staticmethod
    def _infer_scheduled_tasks(reg_changes: List[RegistryChange]) -> List[ScheduledTaskChange]:
        # Heuristic: TaskCache or Schedule keys often show up when tasks are created.
        tasks: Dict[str, ScheduledTaskChange] = {}
        for rc in reg_changes:
            if "TaskCache" not in rc.path and "Schedule" not in rc.path:
                continue
            name = rc.path.rsplit("\\", 1)[-1].strip()
            if not name:
                continue
            tasks.setdefault(name, ScheduledTaskChange(name=name))
        return sorted(tasks.values(), key=lambda t: t.name.lower())

