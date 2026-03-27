"""
Thin FastAPI wrapper around TraceWorker.

This keeps the HTTP layer minimal and leaves the core orchestration in
`TraceWorker` for reuse by:
- CLI (`pkgprobe-trace`)
- Local HTTP service (this module)
- Future queue workers

Security note:
This endpoint executes installers in a VM. Run it only on trusted networks and
consider adding:
- authn/authz
- rate limiting / job quotas
- per-job output directory isolation
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from .diff_engine import DiffEngine
from .installer_executor import InstallerExecutionConfig, InstallerExecutor
from .procmon_controller import ProcmonConfig, ProcmonController
from .trace_worker import TraceWorker, TraceWorkerConfig, TraceWorkerError
from .vmware_controller import VMwareController, VMwareControllerConfig


def create_app(
    *,
    vmx_path: str,
    snapshot_name: str,
    guest_username: str,
    guest_password: str,
    base_output_dir: str,
    vmrun_path: str = "vmrun",
) -> FastAPI:
    """
    Create a FastAPI app bound to a specific trace VM configuration.

    The API accepts an installer upload and runs a trace, returning InstallPlan JSON.
    """
    app = FastAPI(title="pkgprobe-trace", version="0.1")
    base_dir = Path(base_output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    def _make_worker(
        *,
        output_dir: str,
        silent_args: List[str],
        boot_wait_sec: int,
        procmon_path: str,
        guest_installer_path: str,
        guest_pml_path: str,
        guest_csv_path: str,
    ) -> TraceWorker:
        vmware = VMwareController(
            VMwareControllerConfig(
                vmx_path=vmx_path,
                snapshot_name=snapshot_name,
                guest_username=guest_username,
                guest_password=guest_password,
                vmrun_path=vmrun_path,
            )
        )
        procmon = ProcmonController(
            vmware,
            ProcmonConfig(procmon_path=procmon_path, backing_pml=guest_pml_path),
        )
        installer = InstallerExecutor(
            vmware,
            InstallerExecutionConfig(
                guest_installer_path=guest_installer_path,
                silent_args=silent_args,
            ),
        )
        return TraceWorker(
            vmware=vmware,
            procmon=procmon,
            installer_executor=installer,
            diff_engine=DiffEngine(),
            config=TraceWorkerConfig(
                host_output_dir=output_dir,
                guest_pml_path=guest_pml_path,
                guest_csv_path=guest_csv_path,
                host_pml_name="trace.pml",
                host_csv_name="trace.csv",
                boot_wait_sec=boot_wait_sec,
            ),
        )

    @app.post("/trace/run")
    async def run_trace(
        installer: UploadFile = File(...),
        silent_args: Optional[str] = Form("/S"),
        boot_wait_sec: int = Form(30),
        procmon_path: str = Form(r"C:\trace\tools\procmon.exe"),
        guest_installer_path: str = Form(r"C:\trace\installer.exe"),
        guest_pml_path: str = Form(r"C:\trace\logs\trace.pml"),
        guest_csv_path: str = Form(r"C:\trace\logs\trace.csv"),
    ):
        job_id = str(uuid.uuid4())
        job_dir = base_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        host_installer_path = str(job_dir / (installer.filename or "installer.bin"))
        content = await installer.read()
        with open(host_installer_path, "wb") as f:
            f.write(content)

        args_list = [a for a in (silent_args or "").split(" ") if a]
        if not args_list:
            args_list = ["/S"]

        worker = _make_worker(
            output_dir=str(job_dir),
            silent_args=args_list,
            boot_wait_sec=boot_wait_sec,
            procmon_path=procmon_path,
            guest_installer_path=guest_installer_path,
            guest_pml_path=guest_pml_path,
            guest_csv_path=guest_csv_path,
        )

        install_cmd_display = f"{os.path.basename(host_installer_path)} " + " ".join(args_list)
        try:
            plan = worker.run_trace(
                host_installer_path=host_installer_path,
                install_command_display=install_cmd_display.strip(),
            )
        except TraceWorkerError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return plan.to_json_dict()

    return app

