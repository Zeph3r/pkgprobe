"""
Build draft detection previews from an InstallPlan + diff output.

Authoritative eligibility scoring and Intune packaging gating run only on
api.pkgprobe.io (see backend app/services/verification_policy.py).

OSS emits:
- trace_contract.json (install plan + raw diff for the API policy engine)
- verified_manifest.json as a **draft** preview (draft=True, verified=False).
"""

from __future__ import annotations

import re
import warnings
from typing import List

from .diff_engine import DiffResult, FileChange, RegistryChange
from .installplan_generator import InstallPlan
from .verified_manifest import DetectionCandidate, VerifiedTraceManifest


_UNINSTALL_RE = re.compile(r"\\Uninstall\\", re.IGNORECASE)
_MSI_GUID_IN_PATH_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
    re.IGNORECASE,
)
_EXTRACT_GUID_RE = re.compile(
    r"(\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})",
    re.IGNORECASE,
)
_DISPLAY_VERSION_RE = re.compile(r"\\DisplayVersion$", re.IGNORECASE)
_PROGRAM_FILES_RE = re.compile(r"\\Program Files( \\(x86\\))?\\", re.IGNORECASE)
_VMWARE_PF_RE = re.compile(
    r"\\Program Files( \(x86\))?\\(Common Files\\)?VMware(\\|$)",
    re.IGNORECASE,
)
_TEMP_HINT_RE = re.compile(r"\\(Temp|AppData\\Local\\Temp)\\", re.IGNORECASE)


def _parse_silent_args_from_install_command(install_command: str) -> List[str]:
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


def _build_version_index(registry: List[RegistryChange]) -> dict[str, str]:
    """Map lowercased Uninstall key prefix to the GUID found in DisplayVersion write paths."""
    idx: dict[str, str] = {}
    for r in registry:
        path = r.path or ""
        if not _DISPLAY_VERSION_RE.search(path):
            continue
        if not _UNINSTALL_RE.search(path):
            continue
        m = _EXTRACT_GUID_RE.search(path)
        if not m:
            continue
        key_prefix = path[: path.lower().rfind("\\displayversion")].lower()
        idx[key_prefix] = m.group(1)
    return idx


def _msi_product_code_candidates(registry: List[RegistryChange], limit: int = 5) -> List[DetectionCandidate]:
    out: List[DetectionCandidate] = []
    seen: set[str] = set()
    for r in registry:
        path = r.path or ""
        if not path or not _UNINSTALL_RE.search(path):
            continue
        if not _MSI_GUID_IN_PATH_RE.search(path):
            continue
        base = path.split("\\DisplayVersion")[0] if "\\DisplayVersion" in path else path
        lk = base.lower()
        if lk in seen:
            continue
        seen.add(lk)
        out.append(
            DetectionCandidate(
                type="msi_product_code",
                value=base,
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
            keys.append(path)
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


def collect_detection_candidates(
    *, plan: InstallPlan, diff: DiffResult, product_version: str = "",
) -> List[DetectionCandidate]:
    """Heuristic detection candidates for local preview only (not eligibility scoring)."""
    msi_cands = _msi_product_code_candidates(diff.registry)
    if product_version:
        msi_cands = [
            DetectionCandidate(
                type=c.type,
                value=c.value,
                confidence=c.confidence,
                rationale=c.rationale,
                version=product_version,
                version_operator="ge",
            )
            for c in msi_cands
        ]
    candidates: List[DetectionCandidate] = []
    candidates.extend(msi_cands)
    candidates.extend(_best_uninstall_key_candidates(diff.registry))
    candidates.extend(_best_file_candidates(diff.files))
    candidates.extend(_service_candidates(diff))
    candidates.extend(_task_candidates(diff))
    return candidates


def build_draft_manifest(
    *,
    plan: InstallPlan,
    diff: DiffResult,
    installer_filename: str,
    install_exe_name: str,
    silent_args: List[str] | None = None,
    product_version: str = "",
    product_code: str = "",
) -> VerifiedTraceManifest:
    """Non-authoritative manifest preview; packaging eligibility requires api.pkgprobe.io."""
    silent = silent_args if silent_args is not None else _parse_silent_args_from_install_command(plan.install_command)
    candidates = collect_detection_candidates(plan=plan, diff=diff, product_version=product_version)
    notes = [
        "Draft preview only. Authoritative verified manifest and Intune eligibility are produced by api.pkgprobe.io.",
    ]
    return VerifiedTraceManifest(
        installer_filename=installer_filename,
        install_exe_name=install_exe_name,
        silent_args=list(silent),
        detection_candidates=candidates,
        verified=False,
        verification_errors=[],
        notes=notes,
        draft=True,
        verification_authority="local_draft",
        product_version=product_version,
        product_code=product_code,
    )


def build_verified_manifest(
    *,
    plan: InstallPlan,
    diff: DiffResult,
    installer_filename: str,
    install_exe_name: str,
    silent_args: List[str] | None = None,
    verification_strictness: str = "balanced",
    product_version: str = "",
    product_code: str = "",
) -> VerifiedTraceManifest:
    """
    Deprecated: OSS no longer performs eligibility scoring.

    Returns the same as :func:`build_draft_manifest` (verification_strictness is ignored).
    """
    warnings.warn(
        "build_verified_manifest is deprecated; use build_draft_manifest. "
        "Eligibility scoring runs on api.pkgprobe.io only.",
        DeprecationWarning,
        stacklevel=2,
    )
    return build_draft_manifest(
        plan=plan,
        diff=diff,
        installer_filename=installer_filename,
        install_exe_name=install_exe_name,
        silent_args=silent_args,
        product_version=product_version,
        product_code=product_code,
    )
