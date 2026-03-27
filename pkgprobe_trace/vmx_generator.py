"""
Generate a reasonable VMware Workstation `.vmx` template for Trace VMs.

Important constraints
---------------------
`vmrun` can control an existing VM, but it does not reliably create a new VM
from scratch (OS install + disks + VMware Tools + snapshots).

So this generator focuses on what *is* deterministic and useful:
- Create a VM directory
- Write a VMX file with sane defaults for an automated tracing guest
- Optionally reference a VMDK you already created (or will create in the UI)

You can then open the `.vmx` in VMware Workstation, attach/adjust:
- Virtual disk (`.vmdk`)
- ISO / installation media
- Networking mode
- Guest OS install
- Install VMware Tools
- Create snapshot `TRACE_BASE`
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import os
import shutil
import subprocess


@dataclass(frozen=True)
class VmxTemplateConfig:
    """
    Basic VMX template parameters.

    Attributes
    ----------
    vm_name:
        Display name of the VM in Workstation.
    guest_os:
        Workstation guestOS identifier. Common examples:
        - "windows9srv-64" (Windows Server 2016/2019-ish)
        - "windows2019srv-64"
        Exact values vary; adjust as needed for your Workstation build.
    mem_mb:
        Memory allocation.
    numvcpus:
        Number of vCPUs.
    disk_vmdk_filename:
        VMDK filename (relative to the VM directory). If provided, it will be
        referenced by the VMX (you still need to create the VMDK).
    """

    vm_name: str = "TraceVM"
    guest_os: str = "windows9srv-64"
    mem_mb: int = 4096
    numvcpus: int = 2
    disk_vmdk_filename: Optional[str] = "disk.vmdk"


def default_trace_vm_dir(*, base_dir: Optional[Path] = None, vm_name: str = "TraceVM") -> Path:
    """
    Return a host path that 'makes sense' for local runs.

    Default: `%LOCALAPPDATA%\\pkgprobe\\trace-vms\\<vm_name>` on Windows.
    Falls back to `~/.local/share/pkgprobe/trace-vms/<vm_name>` on other OSes.
    """
    if base_dir is not None:
        return base_dir / vm_name

    # Windows-friendly default
    localapp = Path.home() / "AppData" / "Local"
    return localapp / "pkgprobe" / "trace-vms" / vm_name


def render_vmx(cfg: VmxTemplateConfig) -> str:
    """
    Render a minimal but usable VMX configuration.
    """
    lines = [
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "16"',
        f'displayName = "{cfg.vm_name}"',
        f'guestOS = "{cfg.guest_os}"',
        "",
        f"memsize = \"{cfg.mem_mb}\"",
        f"numvcpus = \"{cfg.numvcpus}\"",
        "",
        # Networking - NAT is often simplest for local, but can be changed in UI.
        "ethernet0.present = \"TRUE\"",
        "ethernet0.connectionType = \"nat\"",
        "ethernet0.virtualDev = \"vmxnet3\"",
        "",
        # SCSI controller
        "scsi0.present = \"TRUE\"",
        "scsi0.virtualDev = \"lsisas1068\"",
        "",
        # Helpful for automation determinism
        "tools.syncTime = \"TRUE\"",
        "gui.exitAtPowerOff = \"TRUE\"",
        "",
    ]

    if cfg.disk_vmdk_filename:
        lines.extend(
            [
                "scsi0:0.present = \"TRUE\"",
                "scsi0:0.deviceType = \"scsi-hardDisk\"",
                f"scsi0:0.fileName = \"{cfg.disk_vmdk_filename}\"",
                "",
            ]
        )

    return "\n".join(lines).rstrip() + "\n"


def write_vmx(
    *,
    vm_dir: Path,
    cfg: VmxTemplateConfig,
    vmx_filename: str = "TraceVM.vmx",
    overwrite: bool = False,
) -> Path:
    """
    Create `vm_dir` and write a VMX file.

    Returns the path to the written `.vmx`.
    """
    vm_dir.mkdir(parents=True, exist_ok=True)
    vmx_path = vm_dir / vmx_filename
    if vmx_path.exists() and not overwrite:
        raise FileExistsError(str(vmx_path))

    vmx_path.write_text(render_vmx(cfg), encoding="utf-8")
    return vmx_path


def find_vdiskmanager_exe(explicit_path: Optional[str] = None) -> Optional[Path]:
    """
    Find `vmware-vdiskmanager.exe` if present.

    Search order:
    - explicit_path (if provided)
    - PATH (via shutil.which)
    - common VMware Workstation install directories on Windows
    """
    candidates: List[Path] = []

    if explicit_path:
        candidates.append(Path(explicit_path))

    which = shutil.which("vmware-vdiskmanager.exe")
    if which:
        candidates.append(Path(which))

    if os.name == "nt":
        pf = os.environ.get("ProgramFiles")
        pf86 = os.environ.get("ProgramFiles(x86)")
        for base in [pf, pf86]:
            if not base:
                continue
            candidates.append(Path(base) / "VMware" / "VMware Workstation" / "vmware-vdiskmanager.exe")

    for c in candidates:
        try:
            if c.is_file():
                return c
        except OSError:
            continue
    return None


def try_create_vmdk(
    *,
    vm_dir: Path,
    vmdk_filename: str,
    size_gb: int,
    vdiskmanager_path: Optional[str] = None,
    overwrite: bool = False,
    timeout_sec: int = 120,
) -> Optional[Path]:
    """
    Best-effort VMDK creation using `vmware-vdiskmanager.exe` if available.

    Parameters
    ----------
    vm_dir:
        Directory that will contain the VMDK.
    vmdk_filename:
        Filename for the VMDK inside vm_dir (e.g. "disk.vmdk").
    size_gb:
        Size in GiB.
    vdiskmanager_path:
        Optional explicit path to `vmware-vdiskmanager.exe`.
    overwrite:
        If True, allows overwriting an existing VMDK file.
    timeout_sec:
        Timeout for the vdiskmanager command.

    Returns
    -------
    Path | None
        Path to created VMDK, or None if vdiskmanager is not available.
    """
    exe = find_vdiskmanager_exe(vdiskmanager_path)
    if exe is None:
        return None

    if size_gb <= 0:
        raise ValueError("size_gb must be > 0")

    vm_dir.mkdir(parents=True, exist_ok=True)
    vmdk_path = vm_dir / vmdk_filename

    if vmdk_path.exists() and not overwrite:
        raise FileExistsError(str(vmdk_path))

    # -c create, -s size, -a adapter, -t disk type
    # Using SCSI and "single growable" type (0) as a reasonable default.
    args = [
        str(exe),
        "-c",
        "-s",
        f"{size_gb}GB",
        "-a",
        "lsilogic",
        "-t",
        "0",
        str(vmdk_path),
    ]

    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]

    proc = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        check=False,
        creationflags=creationflags,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"vmware-vdiskmanager failed with exit code {proc.returncode} "
            f"(stdout={proc.stdout!r}, stderr={proc.stderr!r})"
        )

    return vmdk_path

