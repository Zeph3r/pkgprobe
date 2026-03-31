"""
Build a VerifiedTraceManifest from an InstallPlan + diff output.

Heuristics focus on Intune-friendly detection:
- Prefer Uninstall registry keys when present
- Prefer stable Program Files paths over temp/cache paths
- Include service/task hints as additional candidates
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict
from typing import List

from .diff_engine import DiffResult, FileChange, RegistryChange
from .installplan_generator import InstallPlan
from .verified_manifest import DetectionCandidate, VerifiedTraceManifest


_UNINSTALL_RE = re.compile(r"\\Uninstall\\", re.IGNORECASE)
_MSI_GUID_IN_PATH_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
    re.IGNORECASE,
)
_PROGRAM_FILES_RE = re.compile(r"\\Program Files( \\(x86\\))?\\", re.IGNORECASE)
_VMWARE_PF_RE = re.compile(
    r"\\Program Files( \(x86\))?\\(Common Files\\)?VMware(\\|$)",
    re.IGNORECASE,
)
_TEMP_HINT_RE = re.compile(r"\\(Temp|AppData\\Local\\Temp)\\", re.IGNORECASE)
_NOISY_HINT_RE = re.compile(r"\\(Windows\\Prefetch|Windows\\Temp|ProgramData\\Package Cache)\\", re.IGNORECASE)


def _parse_silent_args_from_install_command(install_command: str) -> List[str]:
    # install_command is stored as a display string; keep this conservative.
    # Prefer callers (CLI/backend) to pass args explicitly, but this gives a
    # fallback so manifest is still useful.
    parts = install_command.strip().split()
    if len(parts) <= 1:
        return []
    return parts[1:]


def _best_file_candidates(files: List[FileChange], limit: int = 5) -> List[DetectionCandidate]:
    cands: List[DetectionCandidate] = []
    for f in files:
        p = f.path or ""
        if not p:
            continue
        if _TEMP_HINT_RE.search(p):
            continue
        if _VMWARE_PF_RE.search(p):
            continue
        if not _PROGRAM_FILES_RE.search(p):
            continue
        # Prefer created files (often main exe/dll) over modified.
        base_conf = 0.75 if f.change_type == "create" else 0.6
        cands.append(
            DetectionCandidate(
                type="file_exists",
                value=p,
                confidence=base_conf,
                rationale="Observed filesystem activity in Program Files",
            )
        )
        if len(cands) >= limit:
            break
    return cands


def _msi_product_code_candidates(registry: List[RegistryChange], limit: int = 5) -> List[DetectionCandidate]:
    out: List[DetectionCandidate] = []
    seen = set()
    for r in registry:
        path = r.path or ""
        if not path or not _UNINSTALL_RE.search(path):
            continue
        if not _MSI_GUID_IN_PATH_RE.search(path):
            continue
        lk = path.lower()
        if lk in seen:
            continue
        seen.add(lk)
        out.append(
            DetectionCandidate(
                type="msi_product_code",
                value=path,
                confidence=0.95,
                rationale="MSI ProductCode (GUID under Uninstall)",
            )
        )
        if len(out) >= limit:
            break
    return out


def _best_uninstall_key_candidates(registry: List[RegistryChange], limit: int = 5) -> List[DetectionCandidate]:
    keys = []
    for r in registry:
        path = r.path or ""
        if not path:
            continue
        if _UNINSTALL_RE.search(path):
            if _MSI_GUID_IN_PATH_RE.search(path):
                continue
            # Registry CSV paths may include value names. Keep full path; detection can use Test-Path.
            keys.append(path)
    # Deduplicate while keeping order
    seen = set()
    uniq = []
    for k in keys:
        lk = k.lower()
        if lk in seen:
            continue
        seen.add(lk)
        uniq.append(k)
        if len(uniq) >= limit:
            break
    return [
        DetectionCandidate(
            type="registry_key",
            value=k,
            confidence=0.9,
            rationale="Observed registry activity under Uninstall (good Intune detection anchor)",
        )
        for k in uniq
    ]


def _service_candidates(diff: DiffResult, limit: int = 5) -> List[DetectionCandidate]:
    out: List[DetectionCandidate] = []
    for svc in diff.services[:limit]:
        out.append(
            DetectionCandidate(
                type="service_exists",
                value=svc.name,
                confidence=0.7,
                rationale="Service inferred from registry activity under CurrentControlSet\\Services",
            )
        )
    return out


def _task_candidates(diff: DiffResult, limit: int = 5) -> List[DetectionCandidate]:
    out: List[DetectionCandidate] = []
    for t in diff.scheduled_tasks[:limit]:
        out.append(
            DetectionCandidate(
                type="scheduled_task_exists",
                value=t.name,
                confidence=0.6,
                rationale="Scheduled task inferred from registry activity",
            )
        )
    return out


def build_verified_manifest(
    *,
    plan: InstallPlan,
    diff: DiffResult,
    installer_filename: str,
    install_exe_name: str,
    silent_args: List[str] | None = None,
) -> VerifiedTraceManifest:
    silent = silent_args if silent_args is not None else _parse_silent_args_from_install_command(plan.install_command)

    candidates: List[DetectionCandidate] = []
    candidates.extend(_msi_product_code_candidates(diff.registry))
    candidates.extend(_best_uninstall_key_candidates(diff.registry))
    candidates.extend(_best_file_candidates(diff.files))
    candidates.extend(_service_candidates(diff))
    candidates.extend(_task_candidates(diff))

    # ---- Verification criteria (strict) ---------------------------------
    #
    # For `.intunewin` packaging, we require at least one *strong* detection
    # anchor that is stable across machines:
    # - Uninstall registry key activity (preferred)
    # - Program Files file path (acceptable)
    #
    # Service/task-only detection is considered too weak by default.
    verification_errors: List[str] = []
    notes: List[str] = []

    strong = []
    for c in candidates:
        if c.type == "msi_product_code":
            strong.append(c)
        elif c.type == "registry_key" and _UNINSTALL_RE.search(c.value):
            strong.append(c)
        elif c.type == "file_exists" and _PROGRAM_FILES_RE.search(c.value) and not _TEMP_HINT_RE.search(c.value):
            strong.append(c)

    # Filter out obviously noisy anchors
    strong = [c for c in strong if not _NOISY_HINT_RE.search(c.value)]

    if not silent:
        verification_errors.append("No silent args were provided/detected; refusing to package without a verified silent command.")

    if not strong:
        verification_errors.append(
            "No strong detection anchors found (need Uninstall registry key or Program Files file)."
        )

    # Require at least one high-confidence anchor.
    if strong and max(float(c.confidence) for c in strong) < 0.85:
        verification_errors.append("Detection anchors exist but confidence is too low (<0.85).")

    # If we found only service/task candidates, be explicit.
    if not strong and (diff.services or diff.scheduled_tasks):
        notes.append("Only service/task hints were detected; these are not sufficient alone for Intune detection.")

    return VerifiedTraceManifest(
        installer_filename=installer_filename,
        install_exe_name=install_exe_name,
        silent_args=list(silent),
        detection_candidates=candidates,
        verified=len(verification_errors) == 0,
        verification_errors=verification_errors,
        notes=notes,
    )

