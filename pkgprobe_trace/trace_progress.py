"""Write coarse-grained trace stage to the host output dir for API polling / logging."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

TRACE_PROGRESS_FILENAME = "trace_progress.json"


class TraceProgressError(RuntimeError):
    """Wall-clock or per-stage stall limit exceeded."""



# Stages surfaced to GET /jobs/{id} via the API progress watcher
STAGE_BOOTING_VM = "booting_vm"
STAGE_UPLOADING = "uploading"
STAGE_RUNNING_INSTALLER = "running_installer"
STAGE_STOPPING_PROCMON = "stopping_procmon"
STAGE_EXPORTING_TRACE = "exporting_trace"
STAGE_PARSING = "parsing"
STAGE_GENERATING_OUTPUT = "generating_output"
STAGE_GENERATING_WRAPPER = "generating_wrapper"
STAGE_VERIFYING_WRAPPER = "verifying_wrapper"


def write_trace_progress(host_output_dir: str, stage: str) -> None:
    """Atomic JSON write for pollers (API reads ``trace_progress.json``)."""
    out = Path(host_output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / TRACE_PROGRESS_FILENAME
    payload = {
        "stage": stage,
        "unix_time": time.time(),
        "monotonic": time.monotonic(),
    }
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(path)
    logger.info("trace stage → %s", stage)


class TraceStageTracker:
    """
    Enforce optional wall-clock and per-stage (stall) limits; emit progress JSON.
    Call :meth:`touch` from long inner loops (e.g. waiting for msiexec).
    """

    def __init__(
        self,
        host_output_dir: str,
        *,
        stuck_stage_timeout_sec: float,
        wall_clock_sec: float,
        stage_timeouts_sec: dict[str, float] | None = None,
    ) -> None:
        self._host_output_dir = host_output_dir
        self._stuck = float(stuck_stage_timeout_sec)
        self._wall = float(wall_clock_sec)
        self._run_start = time.monotonic()
        self._stage_start = time.monotonic()
        self._current: str | None = None
        self._stage_timeouts_sec = dict(stage_timeouts_sec or {})

    def set_stage(self, stage: str) -> None:
        self._check_wall()
        self._current = stage
        self._stage_start = time.monotonic()
        write_trace_progress(self._host_output_dir, stage)

    def touch(self) -> None:
        """Raise if wall clock or current stage exceeded stuck timeout."""
        self._check_wall()
        if self._current is None:
            return
        elapsed = time.monotonic() - self._stage_start
        lim = self._stage_timeouts_sec.get(self._current, 0.0)
        if lim > 0 and elapsed > lim:
            raise TraceProgressError(
                f"Stage {self._current!r} exceeded stage timeout {lim:.0f}s"
            )
        if elapsed > self._stuck:
            raise TraceProgressError(
                f"Stuck in stage {self._current!r} for more than {self._stuck:.0f}s"
            )

    def _check_wall(self) -> None:
        if self._wall <= 0:
            return
        if time.monotonic() - self._run_start > self._wall:
            raise TraceProgressError(
                f"Trace wall-clock limit exceeded ({self._wall:.0f}s)"
            )
