"""
Internal analyzer telemetry for debugging heuristic decisions.

Off by default. Enable via PKGPROBE_TELEMETRY=1 env var or --telemetry CLI flag.
Events are emitted as JSON lines to stderr (or a configurable sink).
This is diagnostic logging for heuristic tuning, not user-facing analytics.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass
class AnalyzerEvent:
    timestamp: str
    event_type: str
    data: dict[str, Any] = field(default_factory=dict)


_SinkFn = Callable[[AnalyzerEvent], None]


def _stderr_sink(event: AnalyzerEvent) -> None:
    line = json.dumps(asdict(event), default=str)
    print(line, file=sys.stderr)


class AnalyzerTelemetry:
    """Lightweight event recorder for analyzer decisions."""

    def __init__(
        self,
        enabled: bool = False,
        sink: _SinkFn | None = None,
    ) -> None:
        self._enabled = enabled
        self._sink = sink or _stderr_sink
        self._events: list[AnalyzerEvent] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    def record(self, event_type: str, **data: Any) -> None:
        if not self._enabled:
            return
        event = AnalyzerEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            data=data,
        )
        self._events.append(event)
        self._sink(event)

    def get_events(self) -> list[AnalyzerEvent]:
        return list(self._events)


_global_telemetry: AnalyzerTelemetry | None = None


def get_telemetry() -> AnalyzerTelemetry:
    """Return the global telemetry instance, creating one if needed."""
    global _global_telemetry
    if _global_telemetry is None:
        enabled = os.environ.get("PKGPROBE_TELEMETRY", "0") == "1"
        _global_telemetry = AnalyzerTelemetry(enabled=enabled)
    return _global_telemetry


def init_telemetry(enabled: bool, sink: _SinkFn | None = None) -> AnalyzerTelemetry:
    """Initialize (or re-initialize) the global telemetry instance."""
    global _global_telemetry
    _global_telemetry = AnalyzerTelemetry(enabled=enabled, sink=sink)
    return _global_telemetry
