from __future__ import annotations

import hashlib
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Literal, Optional, Tuple
from uuid import UUID, uuid4

from pkgprobe.models import (
    FileRoot,
    MsiexecPivot,
    Sha256Str,
    TraceAttemptSummary,
    TraceBundle,
    TraceEvent,
    TraceManifest,
    TraceSummary,
    UninstallEntry,
)

PrivacyProfile = Literal["community", "team", "enterprise"]
SUCCESS_CODES = {0, 3010}
EARLY_EXIT_THRESHOLD = 0.85


def _sha256_file(path: Path) -> Sha256Str:
    h = hashlib.sha256()
    with path.open("rb", buffering=1024 * 1024) as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_os_version() -> str:
    return f"{platform.system()} {platform.release()} ({platform.version()})"


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _snapshot_uninstall() -> Dict[str, UninstallEntry]:
    """
    Snapshot uninstall entries from common Windows registry locations.

    Returns:
        Mapping key -> UninstallEntry, where key is a stable identifier
        (product_code if present, otherwise uninstall_string or display_name).
    """
    entries: Dict[str, UninstallEntry] = {}

    if not _is_windows():
        return entries

    try:
        import winreg  # type: ignore
    except Exception:
        return entries

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ]

    for root, subkey in roots:
        try:
            hkey = winreg.OpenKey(root, subkey)
        except OSError:
            continue

        with hkey:
            i = 0
            while True:
                try:
                    name = winreg.EnumKey(hkey, i)
                except OSError:
                    break
                i += 1

                try:
                    app_key = winreg.OpenKey(hkey, name)
                except OSError:
                    continue

                with app_key:
                    def _get_value(vname: str) -> str | None:
                        try:
                            val, _ = winreg.QueryValueEx(app_key, vname)
                            if isinstance(val, str) and val.strip():
                                return val
                        except OSError:
                            return None
                        return None

                    display_name = _get_value("DisplayName")
                    display_version = _get_value("DisplayVersion")
                    publisher = _get_value("Publisher")
                    uninstall_string = _get_value("UninstallString")
                    quiet_uninstall_string = _get_value("QuietUninstallString")
                    product_code = _get_value("ProductID") or _get_value("ProductCode")
                    install_location = _get_value("InstallLocation")

                    if not (display_name or uninstall_string or product_code):
                        continue

                    key = (
                        product_code
                        or uninstall_string
                        or display_name
                        or f"{subkey}\\{name}"
                    )

                    install_location_hash: Sha256Str | None = None
                    if install_location:
                        install_location_hash = hashlib.sha256(
                            install_location.encode("utf-8", errors="ignore")
                        ).hexdigest()

                    entries[key] = UninstallEntry(
                        display_name=display_name,
                        display_version=display_version,
                        publisher=publisher,
                        uninstall_string=uninstall_string,
                        quiet_uninstall_string=quiet_uninstall_string,
                        product_code=product_code,
                        install_location_hash=install_location_hash,
                    )

    return entries


def _discover_file_roots() -> Dict[str, Path]:
    roots: Dict[str, Path] = {}
    if not _is_windows():
        return roots

    env = os.environ
    mapping = {
        "program_files": env.get("ProgramFiles"),
        "program_files_x86": env.get("ProgramFiles(x86)"),
        "program_data": env.get("ProgramData"),
        "user_profile": env.get("LOCALAPPDATA"),
        "temp": env.get("TEMP"),
        "windows": env.get("SystemRoot"),
    }
    for root_type, value in mapping.items():
        if not value:
            continue
        p = Path(value)
        if p.exists():
            roots[root_type] = p
    return roots


def _snapshot_file_roots() -> Dict[str, set[Path]]:
    """
    Snapshot candidate install roots by scanning for directories that
    contain at least one .exe file under known root locations.
    """
    roots = _discover_file_roots()
    result: Dict[str, set[Path]] = {k: set() for k in roots.keys()}

    for root_type, base in roots.items():
        for dirpath, _dirnames, filenames in os.walk(base):
            if any(name.lower().endswith(".exe") for name in filenames):
                result[root_type].add(Path(dirpath))

    return result


def _is_msiexec_child_of(parent_pid: int) -> bool:
    """Return True if any msiexec.exe has ParentProcessId == parent_pid (Windows only)."""
    if not _is_windows():
        return False
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter \"name='msiexec.exe' and ParentProcessId={parent_pid}\" | Measure-Object).Count -gt 0",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            return False
        return (r.stdout or "").strip().lower() == "true"
    except (subprocess.TimeoutExpired, OSError):
        return False


def _get_msiexec_cmd_for_parent(parent_pid: int) -> Optional[str]:
    """Get CommandLine of first msiexec.exe whose ParentProcessId == parent_pid (Windows only)."""
    if not _is_windows():
        return None
    try:
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-CimInstance Win32_Process -Filter \"name='msiexec.exe' and ParentProcessId={parent_pid}\" | Select -First 1 -ExpandProperty CommandLine",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0 or not (r.stdout and r.stdout.strip()):
            return None
        return r.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return None


_GUID_RE = re.compile(
    r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
)


def _parse_msiexec_product_code(cmd: str) -> Optional[str]:
    """Extract product code (GUID) from msiexec command line. Does not store or log cmd."""
    if not cmd:
        return None
    m = _GUID_RE.search(cmd)
    return m.group(0) if m else None


def _parse_msiexec_msi_path(cmd: str) -> Optional[Path]:
    """Extract .msi path from msiexec /i or /x argument. Prefers /i path."""
    if not cmd:
        return None
    for flag in ["/i ", "/I "]:
        i = cmd.find(flag)
        if i >= 0:
            rest = cmd[i + len(flag) :].lstrip()
            if rest.startswith('"'):
                end = rest.find('"', 1)
                if end > 0:
                    path = rest[1:end].strip()
                else:
                    path = rest[1:].split()[0] if rest[1:] else None
            else:
                path = rest.split()[0] if rest else None
            if path:
                p = Path(path)
                if p.suffix.lower() == ".msi":
                    return p
    return None


class TraceSession:
    """
    Minimal executable trace session.

    Responsibilities:
    - Preflight: hash + basic metadata
    - Snapshot uninstall entries before and after
    - Execute installer once (no switches yet)
    - Basic success scoring based on exit code + uninstall diff
    - Produce a valid TraceBundle and empty event list
    """

    def __init__(
        self,
        installer_path: Path,
        privacy_profile: PrivacyProfile = "community",
        timeout_seconds: int = 600,
        no_exec: bool = False,
        attempts: Optional[list[str]] = None,
    ) -> None:
        self.installer_path = Path(installer_path)
        self.privacy_profile: PrivacyProfile = privacy_profile
        self.timeout_seconds = timeout_seconds
        self.no_exec = no_exec
        # Default to a single attempt with no switches if none are provided.
        self.attempts: list[str] = attempts or [""]

    def _preflight(self) -> Tuple[UUID, Sha256Str, int, str]:
        if not self.installer_path.is_file():
            raise FileNotFoundError(f"Installer not found: {self.installer_path}")

        trace_id = uuid4()
        sha256 = _sha256_file(self.installer_path)
        size = self.installer_path.stat().st_size
        os_version = _get_os_version()
        return trace_id, sha256, size, os_version

    def _execute_installer(
        self, installer_sha256: Sha256Str, switch: str
    ) -> Tuple[int, int, list[TraceEvent], Optional[MsiexecPivot]]:
        """
        Execute the installer once with no switches.
        Emits process_start and process_exit events.
        Polls for msiexec.exe during execution to detect MSI pivot.

        Returns:
            (exit_code, duration_ms, events, msiexec_pivot)
        """
        events: list[TraceEvent] = []
        image_path_hash = hashlib.sha256(
            str(self.installer_path).encode("utf-8", errors="ignore")
        ).hexdigest()
        msiexec_detected = False
        msiexec_cmd_hash: Optional[Sha256Str] = None
        product_code: Optional[str] = None
        msi_sha256: Optional[Sha256Str] = None

        start = time.monotonic()
        try:
            cmd = [str(self.installer_path)]
            if switch:
                # naive split is acceptable for v1; later we can support
                # more structured switch parsing if needed.
                cmd.extend(switch.split())
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pid = proc.pid
            if pid is not None:
                events.append(
                    TraceEvent(
                        type="process_start",
                        timestamp=datetime.now(timezone.utc),
                        pid=pid,
                        parent_pid=os.getpid(),
                        image_hash=installer_sha256,
                        image_path_hash=image_path_hash,
                    )
                )
            while True:
                try:
                    proc.wait(timeout=1.0)
                    exit_code = proc.returncode if proc.returncode is not None else -1
                    break
                except subprocess.TimeoutExpired:
                    if pid is not None and _is_msiexec_child_of(pid):
                        msiexec_detected = True
                        if msiexec_cmd_hash is None:
                            cmd = _get_msiexec_cmd_for_parent(pid)
                            if cmd:
                                msiexec_cmd_hash = hashlib.sha256(
                                    cmd.encode("utf-8", errors="ignore")
                                ).hexdigest()
                                if product_code is None:
                                    product_code = _parse_msiexec_product_code(cmd)
                                if msi_sha256 is None:
                                    msi_path = _parse_msiexec_msi_path(cmd)
                                    if msi_path and msi_path.is_file():
                                        msi_sha256 = _sha256_file(msi_path)
                    if (time.monotonic() - start) >= self.timeout_seconds:
                        proc.kill()
                        proc.wait()
                        exit_code = -1
                        break
            if pid is not None:
                events.append(
                    TraceEvent(
                        type="process_exit",
                        timestamp=datetime.now(timezone.utc),
                        pid=pid,
                        parent_pid=os.getpid(),
                        image_hash=installer_sha256,
                        image_path_hash=image_path_hash,
                    )
                )
        except OSError:
            exit_code = -1
        duration_ms = int((time.monotonic() - start) * 1000)
        msiexec_pivot = (
            MsiexecPivot(
                detected=True,
                msi_sha256=msi_sha256,
                product_code=product_code,
                msiexec_cmd_hash=msiexec_cmd_hash,
            )
            if msiexec_detected
            else None
        )
        return exit_code, duration_ms, events, msiexec_pivot

    def _run_single_attempt(
        self,
        attempt_index: int,
        switch: str,
        installer_sha256: Sha256Str,
        baseline_uninstall: Dict[str, UninstallEntry],
        baseline_roots: Dict[str, set[Path]],
    ) -> Tuple[
        TraceAttemptSummary,
        list[TraceEvent],
        list[UninstallEntry],
        list[FileRoot],
        Optional[MsiexecPivot],
    ]:
        """
        Run a single attempt using the shared baselines.
        """
        exit_code, duration_ms, events, msiexec_pivot = self._execute_installer(
            installer_sha256, switch
        )

        after_uninstall = _snapshot_uninstall()
        after_roots = _snapshot_file_roots()

        added_keys = [k for k in after_uninstall.keys() if k not in baseline_uninstall]
        added_uninstall_entries = [after_uninstall[k] for k in added_keys]

        added_file_roots: list[FileRoot] = []
        for root_type, after_set in after_roots.items():
            before_set = baseline_roots.get(root_type, set())
            for path in after_set - before_set:
                exe_hashes: list[Sha256Str] = []
                try:
                    for child in path.iterdir():
                        if child.is_file() and child.suffix.lower() == ".exe":
                            exe_hashes.append(_sha256_file(child))
                except OSError:
                    continue

                root_path_hash = hashlib.sha256(
                    str(path).encode("utf-8", errors="ignore")
                ).hexdigest()
                added_file_roots.append(
                    FileRoot(
                        root_type=root_type,
                        root_path_hash=root_path_hash,
                        exe_hashes=exe_hashes,
                    )
                )

        success_score = 0.0
        if exit_code in SUCCESS_CODES:
            success_score += 0.6
        if added_uninstall_entries:
            success_score += 0.4
        if msiexec_pivot is not None and msiexec_pivot.detected:
            success_score += 0.2
        success_score = min(1.0, success_score)

        attempt = TraceAttemptSummary(
            attempt_index=attempt_index,
            switch_string=switch,
            exit_code=exit_code,
            duration_ms=duration_ms,
            ui_detected=False,
            success_score=success_score,
        )

        return attempt, events, added_uninstall_entries, added_file_roots, msiexec_pivot

    def run(self) -> Tuple[TraceBundle, list[TraceEvent]]:
        """
        Run an executable trace session with one or more attempts.

        This implementation:
        - Preflight (hash + metadata)
        - Optionally executes one or more attempts (no_exec skips execution)
        - Uses a shared baseline for uninstall and file roots
        - Scores each attempt independently
        - Selects the best attempt and exposes its score/metadata in the summary
        """
        trace_id, sha256, size, os_version = self._preflight()

        manifest = TraceManifest(
            schema_version="1.0",
            trace_id=trace_id,
            installer_sha256=sha256,
            installer_file_name=os.path.basename(self.installer_path),
            installer_size_bytes=size,
            installer_signer=None,
            timestamp=datetime.now(timezone.utc),
            os_version=os_version,
            machine_type="unknown",
            privacy_profile=self.privacy_profile,
        )

        # No-exec mode: skip execution but honor multi-attempt list so that
        # --try-silent (and explicit --attempt) are visible in dry-run output.
        if self.no_exec:
            no_exec_attempts: list[TraceAttemptSummary] = []
            for idx, switch in enumerate(self.attempts):
                no_exec_attempts.append(
                    TraceAttemptSummary(
                        attempt_index=idx,
                        switch_string=switch,
                        exit_code=0,
                        duration_ms=0,
                        ui_detected=False,
                        success_score=0.0,
                    )
                )
            summary = TraceSummary(
                attempts=no_exec_attempts,
                selected_attempt_index=0,
                install_success_score=0.0,
                msiexec_pivot=None,
                uninstall_entries=[],
                services_added=[],
                tasks_added=[],
                file_roots=[],
            )
            bundle = TraceBundle(manifest=manifest, summary=summary)
            return bundle, []

        baseline_uninstall = _snapshot_uninstall()
        baseline_roots = _snapshot_file_roots()

        attempts: list[TraceAttemptSummary] = []
        all_events: list[TraceEvent] = []
        best_score = 0.0
        best_index = 0
        best_uninst: list[UninstallEntry] = []
        best_roots: list[FileRoot] = []
        best_pivot: Optional[MsiexecPivot] = None

        for idx, switch in enumerate(self.attempts):
            attempt, events, added_uninst, added_roots, pivot = self._run_single_attempt(
                attempt_index=idx,
                switch=switch,
                installer_sha256=sha256,
                baseline_uninstall=baseline_uninstall,
                baseline_roots=baseline_roots,
            )
            attempts.append(attempt)
            all_events.extend(events)

            if attempt.success_score > best_score:
                best_score = attempt.success_score
                best_index = idx
                best_uninst = added_uninst
                best_roots = added_roots
                best_pivot = pivot

            # Early exit: strong success or any uninstall entry detected.
            if attempt.success_score >= EARLY_EXIT_THRESHOLD or added_uninst:
                break

        summary = TraceSummary(
            attempts=attempts,
            selected_attempt_index=best_index,
            install_success_score=best_score,
            msiexec_pivot=best_pivot,
            uninstall_entries=best_uninst,
            services_added=[],
            tasks_added=[],
            file_roots=best_roots,
        )

        bundle = TraceBundle(manifest=manifest, summary=summary)
        return bundle, all_events

