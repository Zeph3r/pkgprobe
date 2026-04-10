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
from typing import Dict, Iterable, List, Literal, Optional, Set

from .trace_noise import should_skip_file_event, should_skip_registry_event

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

    @classmethod
    def from_json_dict(cls, d: Dict[str, object]) -> "DiffResult":
        files_raw = d.get("files") or []
        reg_raw = d.get("registry") or []
        svc_raw = d.get("services") or []
        task_raw = d.get("scheduled_tasks") or []
        if not isinstance(files_raw, list):
            files_raw = []
        if not isinstance(reg_raw, list):
            reg_raw = []
        if not isinstance(svc_raw, list):
            svc_raw = []
        if not isinstance(task_raw, list):
            task_raw = []
        return cls(
            files=[FileChange(**x) for x in files_raw],  # type: ignore[arg-type]
            registry=[RegistryChange(**x) for x in reg_raw],  # type: ignore[arg-type]
            services=[ServiceChange(**x) for x in svc_raw],  # type: ignore[arg-type]
            scheduled_tasks=[ScheduledTaskChange(**x) for x in task_raw],  # type: ignore[arg-type]
        )


def _parse_int_pid(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def _process_name_matches_installer(name: Optional[str], installer_basename: str) -> bool:
    if not name or not installer_basename:
        return False
    n = name.strip().lower()
    b = installer_basename.strip().lower()
    if n == b:
        return True
    return n.endswith("\\" + b)


def build_installer_pid_allowlist(
    csv_paths: Iterable[str],
    installer_image: str,
) -> Optional[Set[int]]:
    """
    Build the set of PIDs in the installer process tree using Parent PID columns.

    Returns None if no root PIDs match ``installer_image`` (caller should treat
    as "do not filter by PID" to avoid dropping real signal).
    """
    pid_to_parent: Dict[int, Optional[int]] = {}
    roots: Set[int] = set()

    for csv_path in csv_paths:
        if not os.path.isfile(csv_path):
            logger.warning("Missing ProcMon CSV for PID scan: %s", csv_path)
            continue
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pid = _parse_int_pid(row.get("PID"))
                if pid is None:
                    continue
                ppid = _parse_int_pid(row.get("Parent PID") or row.get("ParentPID"))
                pid_to_parent[pid] = ppid
                proc = (row.get("Process Name") or row.get("ProcessName") or "").strip()
                if _process_name_matches_installer(proc, installer_image):
                    roots.add(pid)

    if not roots:
        logger.warning(
            "No ProcMon rows for installer image %r; skipping PID tree filter",
            installer_image,
        )
        return None

    allowed = set(roots)
    changed = True
    while changed:
        changed = False
        for pid, ppid in pid_to_parent.items():
            if pid in allowed:
                continue
            if ppid is not None and ppid in allowed:
                allowed.add(pid)
                changed = True

    logger.info(
        "Installer PID tree: %s root process(es), %s total PIDs",
        len(roots),
        len(allowed),
    )
    return allowed


def subtract_baseline_diff(install: DiffResult, baseline: DiffResult) -> DiffResult:
    """Remove paths also present in a baseline (e.g. idle-VM) trace."""
    base_files = {f.path.lower() for f in baseline.files}
    base_reg = {r.path.lower() for r in baseline.registry}
    files = [f for f in install.files if f.path.lower() not in base_files]
    registry = [r for r in install.registry if r.path.lower() not in base_reg]
    services = DiffEngine._infer_services_from_registry(registry)
    tasks = DiffEngine._infer_scheduled_tasks(registry)
    return DiffResult(
        files=files,
        registry=registry,
        services=services,
        scheduled_tasks=tasks,
    )


class DiffEngine:
    """
    Convert ProcMon CSV events into a coarse-grained diff.

    CSV expectations:
    - Has header row.
    - Includes `Operation` and `Path` columns (ProcMon standard export).
    - `Process Name` is used when available.
    - Optional `PID` / `Parent PID` for installer process-tree filtering.

    Rows from known VM/ProcMon/tooling processes and paths (see `trace_noise`)
    are dropped before building the diff.
    """

    FILE_CREATE_OPS = {"CreateFile", "CopyFile"}
    FILE_MODIFY_OPS = {"WriteFile", "SetEndOfFileInformationFile"}
    FILE_DELETE_OPS = {"DeleteFile", "SetDispositionInformationFile"}

    REG_CREATE_OPS = {"RegCreateKey", "RegCreateKeyEx"}
    REG_SET_OPS = {"RegSetValue", "RegSetValueEx"}
    REG_DELETE_KEY_OPS = {"RegDeleteKey", "RegDeleteKeyEx"}
    REG_DELETE_VALUE_OPS = {"RegDeleteValue"}

    def __init__(
        self,
        *,
        installer_process_image: Optional[str] = None,
        include_processes: Optional[List[str]] = None,
        exclude_processes: Optional[List[str]] = None,
        include_path_prefixes: Optional[List[str]] = None,
        exclude_path_prefixes: Optional[List[str]] = None,
        registry_only: bool = False,
        strict_pid_tree: bool = False,
        noise_strictness: str = "balanced",
    ) -> None:
        """
        Parameters
        ----------
        installer_process_image:
            Basename of the uploaded installer in the guest (e.g. ``installer.exe``).
            When set, only events whose PID falls in the installer process tree
            are kept (in addition to path/process noise rules).
        """
        self._installer_process_image = installer_process_image
        self._include_processes = {x.strip().lower() for x in (include_processes or []) if x.strip()}
        self._exclude_processes = {x.strip().lower() for x in (exclude_processes or []) if x.strip()}
        self._include_path_prefixes = [_norm_path(x) for x in (include_path_prefixes or []) if str(x).strip()]
        self._exclude_path_prefixes = [_norm_path(x) for x in (exclude_path_prefixes or []) if str(x).strip()]
        self._registry_only = bool(registry_only)
        self._strict_pid_tree = bool(strict_pid_tree)
        self._noise_strictness = noise_strictness

    def build_diff_from_procmon_csv(self, csv_path: str) -> DiffResult:
        return self.build_diff_from_procmon_csvs([csv_path])

    def build_diff_from_procmon_csvs(
        self,
        csv_paths: Iterable[str],
        *,
        baseline_csv_paths: Optional[Iterable[str]] = None,
    ) -> DiffResult:
        paths = [p for p in csv_paths if p]
        if not paths:
            return DiffResult()

        install_allowlist: Optional[Set[int]] = None
        if self._installer_process_image:
            install_allowlist = build_installer_pid_allowlist(
                paths,
                self._installer_process_image,
            )
        if self._strict_pid_tree and self._installer_process_image and not install_allowlist:
            logger.warning("Strict PID-tree mode: no installer PID roots found; returning empty diff")
            return DiffResult()

        main = self._diff_from_paths(paths, install_allowlist)

        baseline_paths = [p for p in (baseline_csv_paths or []) if p]
        if baseline_paths:
            # Baseline (e.g. boot idle) traces usually do not run the installer;
            # do not apply PID filtering so subtraction matches path-for-path noise.
            base = self._diff_from_paths(baseline_paths, None)
            main = subtract_baseline_diff(main, base)

        return main

    def _diff_from_paths(
        self,
        csv_paths: Iterable[str],
        pid_allowlist: Optional[Set[int]],
    ) -> DiffResult:
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

                    if not self._pass_custom_filters(process=process, path=path):
                        continue

                    if pid_allowlist is not None:
                        pid = _parse_int_pid(row.get("PID"))
                        if pid is not None and pid not in pid_allowlist:
                            continue

                    if op in (
                        self.FILE_CREATE_OPS
                        | self.FILE_MODIFY_OPS
                        | self.FILE_DELETE_OPS
                    ):
                        if should_skip_file_event(process, path, strictness=self._noise_strictness):
                            continue
                    elif op in (
                        self.REG_CREATE_OPS
                        | self.REG_SET_OPS
                        | self.REG_DELETE_KEY_OPS
                        | self.REG_DELETE_VALUE_OPS
                    ):
                        if should_skip_registry_event(process, path, strictness=self._noise_strictness):
                            continue

                    if op in self.FILE_CREATE_OPS:
                        if self._registry_only:
                            continue
                        self._record_file_change(file_changes, path, "create", process)
                        continue
                    if op in self.FILE_MODIFY_OPS:
                        if self._registry_only:
                            continue
                        self._record_file_change(file_changes, path, "modify", process)
                        continue
                    if op in self.FILE_DELETE_OPS:
                        if self._registry_only:
                            continue
                        self._record_file_change(file_changes, path, "delete", process)
                        continue

                    if op in self.REG_CREATE_OPS:
                        reg_changes.append(
                            RegistryChange(path=path, change_type="create_key", process=process)
                        )
                        continue
                    if op in self.REG_SET_OPS:
                        reg_changes.append(
                            RegistryChange(path=path, change_type="set_value", process=process)
                        )
                        continue
                    if op in self.REG_DELETE_KEY_OPS:
                        reg_changes.append(
                            RegistryChange(path=path, change_type="delete_key", process=process)
                        )
                        continue
                    if op in self.REG_DELETE_VALUE_OPS:
                        reg_changes.append(
                            RegistryChange(path=path, change_type="delete_value", process=process)
                        )
                        continue

        files = sorted(file_changes.values(), key=lambda x: x.path.lower())
        services = self._infer_services_from_registry(reg_changes)
        tasks = self._infer_scheduled_tasks(reg_changes)

        return DiffResult(files=files, registry=reg_changes, services=services, scheduled_tasks=tasks)

    def _pass_custom_filters(self, *, process: Optional[str], path: str) -> bool:
        proc = _norm_process(process)
        p = _norm_path(path)
        if self._include_processes and proc not in self._include_processes:
            return False
        if proc and proc in self._exclude_processes:
            return False
        if self._include_path_prefixes and not any(p.startswith(x) for x in self._include_path_prefixes):
            return False
        if self._exclude_path_prefixes and any(p.startswith(x) for x in self._exclude_path_prefixes):
            return False
        return True

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
