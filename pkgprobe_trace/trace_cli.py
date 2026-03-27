"""
CLI entrypoint for local VMware-based tracing.

Console script: `pkgprobe-trace`

Example:
    pkgprobe-trace run installer.exe ^
      --vmx "C:\\VMs\\TraceVM\\TraceVM.vmx" ^
      --snapshot TRACE_BASE ^
      --guest-user Administrator ^
      --guest-pass "Password123!" ^
      --output "C:\\traces\\job-001" ^
      --silent-args /S /NORESTART

This prints InstallPlan JSON to stdout (easy to wrap by a FastAPI service).
"""

from __future__ import annotations

import argparse
import logging
import os
from pathlib import Path
from typing import List, Optional

from .diff_engine import DiffEngine
from .installplan_generator import InstallPlan
from .installer_executor import InstallerExecutionConfig, InstallerExecutor
from .intunewin_packager import IntuneWinPackager, IntuneWinPackagerConfig
from .procmon_controller import ProcmonConfig, ProcmonController
from .trace_worker import TraceWorker, TraceWorkerConfig
from .verified_manifest import VerifiedTraceManifest
from .vmware_controller import VMwareController, VMwareControllerConfig
from .vmx_generator import VmxTemplateConfig, default_trace_vm_dir, try_create_vmdk, write_vmx


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pkgprobe-trace",
        description="Run a Windows installer in a disposable VMware VM and emit an InstallPlan JSON.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init_vm = sub.add_parser("init-vm", help="Generate a TraceVM .vmx template")
    init_vm.add_argument(
        "--dir",
        default="",
        help="Directory to create VM in. If omitted, uses a sensible per-user default.",
    )
    init_vm.add_argument("--name", default="TraceVM", help="VM display name")
    init_vm.add_argument("--vmx-name", default="TraceVM.vmx", help="VMX filename")
    init_vm.add_argument("--guest-os", default="windows9srv-64", help="VMware guestOS id")
    init_vm.add_argument("--mem-mb", type=int, default=4096, help="Memory (MB)")
    init_vm.add_argument("--vcpus", type=int, default=2, help="vCPU count")
    init_vm.add_argument(
        "--disk-vmdk",
        default="disk.vmdk",
        help="VMDK filename referenced by VMX (you must create/attach it in Workstation)",
    )
    init_vm.add_argument(
        "--create-disk",
        action="store_true",
        help="Try to create the VMDK using vmware-vdiskmanager.exe if available",
    )
    init_vm.add_argument(
        "--disk-size-gb",
        type=int,
        default=60,
        help="Disk size in GB when using --create-disk (default: 60)",
    )
    init_vm.add_argument(
        "--vdiskmanager",
        default="",
        help="Optional explicit path to vmware-vdiskmanager.exe",
    )
    init_vm.add_argument("--overwrite", action="store_true", help="Overwrite existing VMX")
    init_vm.add_argument("--verbose", action="store_true", help="Verbose logging")

    run = sub.add_parser("run", help="Trace a single installer")
    run.add_argument("installer", help="Installer path on host")
    run.add_argument("--vmx", required=True, help="Path to VMX file")
    run.add_argument("--snapshot", required=True, help="Clean snapshot name (e.g. TRACE_BASE)")
    run.add_argument("--guest-user", required=True, help="Guest username (VMware Tools auth)")
    run.add_argument("--guest-pass", required=True, help="Guest password (VMware Tools auth)")
    run.add_argument("--output", required=True, help="Output directory on host for trace artifacts")
    run.add_argument("--silent-args", nargs="*", default=["/S"], help="Silent install arguments")
    run.add_argument("--boot-wait", type=int, default=30, help="Seconds to wait after VM start")

    run.add_argument(
        "--procmon-path",
        default=r"C:\trace\tools\procmon.exe",
        help="ProcMon path inside guest",
    )
    run.add_argument(
        "--guest-installer-path",
        default=r"C:\trace\installer.exe",
        help="Installer destination path in guest",
    )
    run.add_argument(
        "--guest-pml",
        default=r"C:\trace\logs\trace.pml",
        help="Guest PML output path",
    )
    run.add_argument(
        "--guest-csv",
        default=r"C:\trace\logs\trace.csv",
        help="Guest CSV output path (export target)",
    )
    run.add_argument(
        "--host-pml-name",
        default="trace.pml",
        help="Filename for PML stored under output dir",
    )
    run.add_argument(
        "--host-csv-name",
        default="trace.csv",
        help="Filename for CSV stored under output dir",
    )
    run.add_argument(
        "--emit-manifest",
        action="store_true",
        help="Write verified manifest JSON into the output directory",
    )
    run.add_argument(
        "--manifest-name",
        default="verified_manifest.json",
        help="Filename for manifest stored under output dir (with --emit-manifest)",
    )
    run.add_argument("--verbose", action="store_true", help="Verbose logging")

    pack = sub.add_parser("pack-intunewin", help="Create a .intunewin package from trace output")
    pack.add_argument(
        "--trace-output",
        required=True,
        help="Trace output directory containing installer + verified_manifest.json",
    )
    pack.add_argument(
        "--installer",
        default="",
        help="Optional explicit path to installer (defaults to first *.exe/*.msi in trace-output)",
    )
    pack.add_argument(
        "--manifest",
        default="",
        help="Optional explicit path to verified manifest (defaults to verified_manifest.json in trace-output)",
    )
    pack.add_argument(
        "--util",
        default="IntuneWinAppUtil.exe",
        help="Path to IntuneWinAppUtil.exe (or rely on PATH)",
    )
    pack.add_argument(
        "--out",
        default="",
        help="Output directory for .intunewin (defaults to trace-output)",
    )
    pack.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing staging/output files when possible",
    )
    pack.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow packaging even if the manifest verification failed (not recommended)",
    )
    pack.add_argument("--verbose", action="store_true", help="Verbose logging")

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    _setup_logging(getattr(args, "verbose", False))

    if args.command == "init-vm":
        base_dir: Optional[Path] = None
        if args.dir:
            base_dir = Path(args.dir)
            vm_dir = base_dir
        else:
            vm_dir = default_trace_vm_dir(vm_name=args.name)

        cfg = VmxTemplateConfig(
            vm_name=args.name,
            guest_os=args.guest_os,
            mem_mb=args.mem_mb,
            numvcpus=args.vcpus,
            disk_vmdk_filename=args.disk_vmdk or None,
        )

        if args.create_disk and args.disk_vmdk:
            created = try_create_vmdk(
                vm_dir=vm_dir,
                vmdk_filename=args.disk_vmdk,
                size_gb=int(args.disk_size_gb),
                vdiskmanager_path=args.vdiskmanager or None,
                overwrite=bool(args.overwrite),
            )
            if created is None:
                logging.getLogger(__name__).warning(
                    "vmware-vdiskmanager.exe not found; skipping VMDK creation"
                )
        vmx_path = write_vmx(
            vm_dir=vm_dir,
            cfg=cfg,
            vmx_filename=args.vmx_name,
            overwrite=bool(args.overwrite),
        )
        print(str(vmx_path))
        return 0

    if args.command != "run":
        if args.command == "pack-intunewin":
            trace_out = Path(args.trace_output)
            out_dir = Path(args.out) if args.out else trace_out
            installer_path = Path(args.installer) if args.installer else None
            manifest_path = Path(args.manifest) if args.manifest else None

            packager = IntuneWinPackager(
                IntuneWinPackagerConfig(
                    intunewin_util_path=args.util,
                    overwrite=bool(args.overwrite),
                    allow_unverified=bool(args.allow_unverified),
                )
            )
            produced = packager.pack_from_trace_output(
                trace_output_dir=trace_out,
                output_dir=out_dir,
                installer_path=installer_path,
                manifest_path=manifest_path,
            )
            print(str(produced))
            return 0

        return 2

    vmware = VMwareController(
        VMwareControllerConfig(
            vmx_path=args.vmx,
            snapshot_name=args.snapshot,
            guest_username=args.guest_user,
            guest_password=args.guest_pass,
        )
    )

    procmon = ProcmonController(
        vmware,
        ProcmonConfig(
            procmon_path=args.procmon_path,
            backing_pml=args.guest_pml,
        ),
    )

    installer_executor = InstallerExecutor(
        vmware,
        InstallerExecutionConfig(
            guest_installer_path=args.guest_installer_path,
            silent_args=args.silent_args,
        ),
    )

    worker = TraceWorker(
        vmware=vmware,
        procmon=procmon,
        installer_executor=installer_executor,
        diff_engine=DiffEngine(),
        config=TraceWorkerConfig(
            host_output_dir=args.output,
            guest_pml_path=args.guest_pml,
            guest_csv_path=args.guest_csv,
            host_pml_name=args.host_pml_name,
            host_csv_name=args.host_csv_name,
            boot_wait_sec=args.boot_wait,
        ),
    )

    install_cmd_display = f"{os.path.basename(args.installer)} " + " ".join(args.silent_args)
    if args.emit_manifest:
        plan, manifest = worker.run_trace_with_manifest(
            host_installer_path=args.installer,
            install_command_display=install_cmd_display.strip(),
            installer_filename=os.path.basename(args.installer),
            install_exe_name=os.path.basename(args.installer),
            silent_args=list(args.silent_args or []),
        )
        manifest_path = Path(args.output) / args.manifest_name
        manifest_path.write_text(manifest.to_json(), encoding="utf-8")
        print(plan.to_json())
    else:
        plan, _diff = worker.run_trace(
            host_installer_path=args.installer,
            install_command_display=install_cmd_display.strip(),
        )
        print(plan.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

