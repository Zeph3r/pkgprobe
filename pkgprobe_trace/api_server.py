"""
ASGI entry point for the pkgprobe production API.

Used by: uvicorn pkgprobe_trace.api_server:app

Reads configuration from environment variables.
"""

from __future__ import annotations

import os

from .api_production import create_production_app

app = create_production_app(
    vmx_path=os.environ.get("TRACE_VMX_PATH", ""),
    snapshot_name=os.environ.get("TRACE_SNAPSHOT_NAME", "TRACE_BASE"),
    guest_username=os.environ.get("TRACE_GUEST_USERNAME", "Administrator"),
    guest_password=os.environ.get("TRACE_GUEST_PASSWORD", ""),
    base_output_dir=os.environ.get("PKGPROBE_BASE_OUTPUT_DIR", "./jobs"),
    vmrun_path=os.environ.get("TRACE_VMRUN_PATH", "vmrun"),
    trace_enabled=os.environ.get("TRACE_ENABLED", "false").lower() in ("true", "1", "yes"),
    enable_billing=bool(os.environ.get("STRIPE_SECRET_KEY", "")),
)
