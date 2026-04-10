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
from .procmon_tuning import parse_procmon_tuning
from .psadt_wrapper import PsadtWrapperConfig
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
    run.add_argument(
        "--boot-wait",
        type=int,
        default=0,
        help="Extra seconds to sleep after VMware Tools are ready (default: 0)",
    )
    run.add_argument(
        "--guest-tools-timeout",
        type=int,
        default=120,
        help="Max seconds to poll vmrun checkToolsState until Tools are running",
    )
    run.add_argument(
        "--vmrun-retries",
        type=int,
        default=2,
        help="Extra vmrun attempts after a failed guest/file operation",
    )
    run.add_argument(
        "--pause-after",
        action="store_true",
        help="Do not revert snapshot after trace (leave VM up for manual inspection)",
    )
    run.add_argument(
        "--host-procmon",
        default="",
        help="Path to procmon.exe on the host: copy PML from guest first, export CSV here (faster on some setups)",
    )
    run.add_argument(
        "--baseline-csv",
        default="",
        help="Host path to a baseline ProcMon CSV (e.g. idle VM) to subtract from this trace",
    )
    run.add_argument(
        "--procmon-profile",
        default="balanced",
        choices=["balanced", "low_noise", "high_fidelity"],
        help="ProcMon/diff tuning profile",
    )
    run.add_argument(
        "--procmon-tuning-json",
        default="",
        help="Optional JSON override for ProcMon/diff tuning",
    )

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
    run.add_argument(
        "--installer-timeout",
        type=int,
        default=120,
        help="Hard timeout (seconds) for vmrun waiting on the primary installer process in the guest",
    )
    run.add_argument(
        "--installer-tail-wait",
        type=int,
        default=600,
        help="After the installer returns, wait up to this many seconds for msiexec to finish",
    )
    run.add_argument(
        "--installer-quiet-window",
        type=int,
        default=10,
        help="Quiet seconds with no installer activity before completion is declared",
    )
    run.add_argument(
        "--installer-min-runtime",
        type=int,
        default=0,
        help="Minimum seconds before quiet-window completion is allowed",
    )
    run.add_argument(
        "--stuck-stage-timeout",
        type=float,
        default=900.0,
        help="Fail if a trace stage does not complete within this many seconds (see trace_progress.json)",
    )
    run.add_argument(
        "--trace-wall-seconds",
        type=float,
        default=0.0,
        help="Fail the entire trace after this many seconds (0 = disabled)",
    )
    run.add_argument("--stage-timeout-boot", type=float, default=0.0, help="Per-stage timeout for booting_vm (0 = disabled)")
    run.add_argument("--stage-timeout-installer", type=float, default=0.0, help="Per-stage timeout for running_installer (0 = disabled)")
    run.add_argument("--stage-timeout-export", type=float, default=0.0, help="Per-stage timeout for exporting_trace (0 = disabled)")
    run.add_argument("--stage-timeout-parse", type=float, default=0.0, help="Per-stage timeout for parsing (0 = disabled)")
    run.add_argument("--stage-timeout-pack", type=float, default=0.0, help="Per-stage timeout for generating_output (0 = disabled)")
    run.add_argument("--baseline-max-age-hours", type=float, default=0.0, help="Ignore baseline CSV older than this many hours (0 = disabled)")
    run.add_argument(
        "--verification-strictness",
        choices=["strict", "balanced", "weak_signal_allowed"],
        default="balanced",
        help="Manifest verification strictness profile",
    )
    run.add_argument(
        "--noise-strictness",
        choices=["conservative", "balanced", "aggressive"],
        default="balanced",
        help="Built-in noise filtering strictness profile",
    )
    run.add_argument(
        "--diagnostics-level",
        choices=["normal", "deep"],
        default="normal",
        help="Troubleshooting verbosity for guest diagnostics",
    )
    run.add_argument(
        "--no-guest-installer-diag",
        action="store_true",
        help="Disable tasklist/wmic guest logging after installer (default: diagnostics on)",
    )
    run.add_argument(
        "--auto-wrap",
        action="store_true",
        help="If silent install fails, generate a PSADT wrapper and verify it in a clean VM",
    )
    run.add_argument(
        "--psadt-toolkit-path",
        default="",
        help="Path to a custom PSADT toolkit dir (defaults to bundled minimal template)",
    )

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
    pack.add_argument(
        "--community-pack",
        action="store_true",
        help="Unsafe local-only alias for --allow-unverified (draft or unverified manifests)",
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
                    allow_unverified=bool(args.allow_unverified) or bool(getattr(args, "community_pack", False)),
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
            vmrun_retries=args.vmrun_retries,
        )
    )
    tuning = parse_procmon_tuning(args.procmon_profile, args.procmon_tuning_json or "")

    procmon = ProcmonController(
        vmware,
        ProcmonConfig(
            procmon_path=args.procmon_path,
            backing_pml=args.guest_pml,
            profile=tuning.profile,
            tuning_json=args.procmon_tuning_json or "",
        ),
    )

    installer_executor = InstallerExecutor(
        vmware,
        InstallerExecutionConfig(
            guest_installer_path=args.guest_installer_path,
            silent_args=args.silent_args,
            timeout_sec=int(args.installer_timeout),
            installer_tail_wait_sec=int(args.installer_tail_wait),
            installer_quiet_window_sec=int(args.installer_quiet_window),
            installer_min_runtime_sec=int(args.installer_min_runtime),
            diagnostics_level=str(args.diagnostics_level),
            guest_diag_after_installer=not bool(args.no_guest_installer_diag),
        ),
    )

    worker = TraceWorker(
        vmware=vmware,
        procmon=procmon,
        installer_executor=installer_executor,
        diff_engine=DiffEngine(
            installer_process_image=os.path.basename(args.guest_installer_path),
            include_processes=tuning.include_processes,
            exclude_processes=tuning.exclude_processes,
            include_path_prefixes=tuning.include_path_prefixes,
            exclude_path_prefixes=tuning.exclude_path_prefixes,
            registry_only=tuning.registry_only,
            strict_pid_tree=tuning.strict_pid_tree,
            noise_strictness=tuning.noise_strictness if tuning.noise_strictness else str(args.noise_strictness),
        ),
        config=TraceWorkerConfig(
            host_output_dir=args.output,
            guest_pml_path=args.guest_pml,
            guest_csv_path=args.guest_csv,
            host_pml_name=args.host_pml_name,
            host_csv_name=args.host_csv_name,
            guest_tools_timeout_sec=args.guest_tools_timeout,
            boot_wait_sec=args.boot_wait,
            pause_after_trace=bool(args.pause_after),
            host_procmon_path=(args.host_procmon or None),
            baseline_csv_path=(args.baseline_csv or None),
            baseline_subtraction=bool(tuning.baseline_subtraction),
            baseline_max_age_hours=float(args.baseline_max_age_hours),
            verification_strictness=tuning.verification_strictness if tuning.verification_strictness else str(args.verification_strictness),
            noise_strictness=tuning.noise_strictness if tuning.noise_strictness else str(args.noise_strictness),
            stuck_stage_timeout_sec=float(args.stuck_stage_timeout),
            trace_wall_clock_sec=float(args.trace_wall_seconds),
            guest_installer_diag=not bool(args.no_guest_installer_diag),
            stage_timeout_boot_sec=float(args.stage_timeout_boot),
            stage_timeout_installer_sec=float(args.stage_timeout_installer),
            stage_timeout_export_sec=float(args.stage_timeout_export),
            stage_timeout_parse_sec=float(args.stage_timeout_parse),
            stage_timeout_pack_sec=float(args.stage_timeout_pack),
            diagnostics_level=str(args.diagnostics_level),
            auto_wrap=bool(args.auto_wrap),
            psadt_wrapper_config=(
                PsadtWrapperConfig(psadt_toolkit_path=args.psadt_toolkit_path or None)
                if args.auto_wrap
                else None
            ),
        ),
    )

    install_cmd_display = f"{os.path.basename(args.installer)} " + " ".join(args.silent_args)

    if args.auto_wrap and args.emit_manifest:
        plan, manifest, was_wrapped = worker.run_trace_with_wrapper_fallback(
            host_installer_path=args.installer,
            install_command_display=install_cmd_display.strip(),
            installer_filename=os.path.basename(args.installer),
            install_exe_name=os.path.basename(args.installer),
            silent_args=list(args.silent_args or []),
        )
        if was_wrapped:
            logging.getLogger(__name__).info(
                "Silent install failed; PSADT wrapper verified and ready."
            )
        manifest_path = Path(args.output) / args.manifest_name
        manifest_path.write_text(manifest.to_json(), encoding="utf-8")
        print(plan.to_json())
    elif args.emit_manifest:
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

