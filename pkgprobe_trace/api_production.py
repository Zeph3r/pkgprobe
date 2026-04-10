"""
Production API for pkgprobe.

Three-tier endpoint structure:
- /v1/analyze   (free)  -- static analysis, no VM needed
- /v1/trace     (pro)   -- VMware trace, returns plan + manifest
- /v1/auto-wrap (paid)  -- trace + PSADT wrapper fallback + .intunewin

Auth, billing, and usage tracking are wired in via dependencies
from api_auth.py and api_usage.py.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from .diff_engine import DiffEngine
from .installer_executor import InstallerExecutionConfig, InstallerExecutor
from .procmon_controller import ProcmonConfig, ProcmonController
from .procmon_tuning import parse_procmon_tuning
from .psadt_wrapper import PsadtWrapperConfig
from .trace_worker import TraceWorker, TraceWorkerConfig, TraceWorkerError
from .vmware_controller import VMwareController, VMwareControllerConfig


def create_production_app(
    *,
    vmx_path: str = "",
    snapshot_name: str = "",
    guest_username: str = "",
    guest_password: str = "",
    base_output_dir: str = "./jobs",
    vmrun_path: str = "vmrun",
    trace_enabled: bool = True,
    enable_billing: bool = True,
) -> FastAPI:
    """
    Create the production pkgprobe API.

    When trace_enabled is False, only /v1/analyze is available (no VM required).
    When enable_billing is True, auth middleware and Stripe billing routes are active.
    """
    app = FastAPI(
        title="pkgprobe API",
        version="0.3.0",
        description="Windows installer intelligence API",
    )
    base_dir = Path(base_output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    if enable_billing:
        from .api_db import init_db, get_session_factory
        from .api_auth import ApiKeyAuthMiddleware
        from .api_webhooks import router as billing_router

        engine = init_db()
        session_factory = get_session_factory(engine)
        app.add_middleware(ApiKeyAuthMiddleware, db_session_factory=session_factory)
        app.include_router(billing_router)

    def _require_trace():
        if not trace_enabled:
            raise HTTPException(
                status_code=503,
                detail="Trace endpoints are not available on this server.",
            )

    def _make_worker(
        *,
        output_dir: str,
        silent_args: List[str],
        auto_wrap: bool = False,
    ) -> TraceWorker:
        tuning = parse_procmon_tuning("balanced", "")
        vmware = VMwareController(
            VMwareControllerConfig(
                vmx_path=vmx_path,
                snapshot_name=snapshot_name,
                guest_username=guest_username,
                guest_password=guest_password,
                vmrun_path=vmrun_path,
                vmrun_retries=2,
            )
        )
        procmon = ProcmonController(
            vmware,
            ProcmonConfig(
                procmon_path=r"C:\trace\tools\procmon.exe",
                backing_pml=r"C:\trace\logs\trace.pml",
                profile=tuning.profile,
            ),
        )
        installer = InstallerExecutor(
            vmware,
            InstallerExecutionConfig(
                guest_installer_path=r"C:\trace\installer.exe",
                silent_args=silent_args,
                timeout_sec=120,
                installer_tail_wait_sec=600,
                guest_diag_after_installer=True,
            ),
        )
        return TraceWorker(
            vmware=vmware,
            procmon=procmon,
            installer_executor=installer,
            diff_engine=DiffEngine(
                installer_process_image="installer.exe",
                include_processes=tuning.include_processes,
                exclude_processes=tuning.exclude_processes,
                include_path_prefixes=tuning.include_path_prefixes,
                exclude_path_prefixes=tuning.exclude_path_prefixes,
                registry_only=tuning.registry_only,
                strict_pid_tree=tuning.strict_pid_tree,
            ),
            config=TraceWorkerConfig(
                host_output_dir=output_dir,
                guest_pml_path=r"C:\trace\logs\trace.pml",
                guest_csv_path=r"C:\trace\logs\trace.csv",
                host_pml_name="trace.pml",
                host_csv_name="trace.csv",
                guest_tools_timeout_sec=120,
                boot_wait_sec=0,
                stuck_stage_timeout_sec=900.0,
                trace_wall_clock_sec=0.0,
                guest_installer_diag=True,
                auto_wrap=auto_wrap,
                psadt_wrapper_config=PsadtWrapperConfig() if auto_wrap else None,
            ),
        )

    # ── /v1/analyze (free tier) ───────────────────────────────────────

    @app.post("/v1/analyze")
    async def analyze(
        installer: UploadFile = File(...),
    ) -> Dict[str, Any]:
        """
        Static analysis only. No VM, no execution.
        Returns an InstallPlan JSON with deployment assessment and packaging tier.
        """
        job_id = str(uuid.uuid4())
        job_dir = base_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        filename = installer.filename or "installer.bin"
        host_path = job_dir / filename
        content = await installer.read()
        host_path.write_bytes(content)

        from pkgprobe.analyzers import analyze_exe, analyze_msi

        ext = Path(filename).suffix.lower().lstrip(".")
        try:
            if ext == "msi":
                plan = analyze_msi(str(host_path))
            elif ext == "exe":
                plan = analyze_exe(str(host_path))
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"Unsupported file type: .{ext}. Provide .msi or .exe",
                )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return plan.model_dump(mode="json")

    # ── /v1/trace (pro tier) ──────────────────────────────────────────

    @app.post("/v1/trace")
    async def trace(
        installer: UploadFile = File(...),
        silent_args: Optional[str] = Form("/S"),
    ) -> Dict[str, Any]:
        """
        Upload an installer, run a VMware trace, return plan + trace contract + draft manifest.
        """
        _require_trace()

        job_id = str(uuid.uuid4())
        job_dir = base_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        filename = installer.filename or "installer.bin"
        host_path = str(job_dir / filename)
        content = await installer.read()
        with open(host_path, "wb") as f:
            f.write(content)

        args_list = [a for a in (silent_args or "").split(" ") if a]
        if not args_list:
            args_list = ["/S"]

        install_cmd_display = f"{filename} " + " ".join(args_list)

        worker = _make_worker(
            output_dir=str(job_dir),
            silent_args=args_list,
        )

        try:
            plan, _diff = worker.run_trace(
                host_installer_path=host_path,
                install_command_display=install_cmd_display.strip(),
            )
        except TraceWorkerError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return {
            "trace_id": job_id,
            "plan": plan.to_json_dict(),
        }

    # ── /v1/auto-wrap (auto-wrap tier) ────────────────────────────────

    @app.post("/v1/auto-wrap")
    async def auto_wrap(
        installer: UploadFile = File(...),
        silent_args: Optional[str] = Form("/S"),
    ) -> Dict[str, Any]:
        """
        Upload an installer, run trace with PSADT wrapper fallback.
        Returns plan + verified manifest + artifact ID for .intunewin download.
        """
        _require_trace()

        job_id = str(uuid.uuid4())
        job_dir = base_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        filename = installer.filename or "installer.bin"
        host_path = str(job_dir / filename)
        content = await installer.read()
        with open(host_path, "wb") as f:
            f.write(content)

        args_list = [a for a in (silent_args or "").split(" ") if a]
        if not args_list:
            args_list = ["/S"]

        install_cmd_display = f"{filename} " + " ".join(args_list)

        worker = _make_worker(
            output_dir=str(job_dir),
            silent_args=args_list,
            auto_wrap=True,
        )

        try:
            plan, manifest, was_wrapped = worker.run_trace_with_wrapper_fallback(
                host_installer_path=host_path,
                install_command_display=install_cmd_display.strip(),
                installer_filename=filename,
                install_exe_name=filename,
                silent_args=args_list,
            )
        except TraceWorkerError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return {
            "trace_id": job_id,
            "plan": plan.to_json_dict(),
            "manifest": manifest.to_json_dict(),
            "was_wrapped": was_wrapped,
        }

    # ── /v1/artifacts/{trace_id} ──────────────────────────────────────

    @app.get("/v1/artifacts/{trace_id}")
    async def get_artifact(trace_id: str):
        """Download the .intunewin artifact for a completed auto-wrap job."""
        job_dir = base_dir / trace_id
        if not job_dir.is_dir():
            raise HTTPException(status_code=404, detail="Job not found")

        intunewin_files = list(job_dir.rglob("*.intunewin"))
        if not intunewin_files:
            raise HTTPException(
                status_code=404,
                detail="No .intunewin artifact found for this job",
            )

        artifact = intunewin_files[0]
        return FileResponse(
            path=str(artifact),
            filename=artifact.name,
            media_type="application/octet-stream",
        )

    # ── Health check ──────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "trace_enabled": trace_enabled,
        }

    return app
