from __future__ import annotations

import gzip
import json
from io import BytesIO
from pathlib import Path
from typing import Iterable
from zipfile import ZIP_DEFLATED, ZipFile

from pkgprobe.models import TraceBundle, TraceEvent


def write_pkgtrace(
    bundle: TraceBundle,
    events: Iterable[TraceEvent],
    out_path: Path,
) -> Path:
    """
    Write a .pkgtrace bundle (ZIP) containing manifest.json, summary.json,
    and events.ndjson.gz.

    Args:
        bundle: In-memory manifest and summary.
        events: Iterable stream of TraceEvent instances.
        out_path: Destination path for the .pkgtrace file.

    Returns:
        The resolved output path.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    manifest_json = json.dumps(
        bundle.manifest.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")

    summary_json = json.dumps(
        bundle.summary.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
    ).encode("utf-8")

    events_buffer = BytesIO()
    with gzip.GzipFile(fileobj=events_buffer, mode="wb") as gz:
        for event in events:
            line = json.dumps(event.model_dump(mode="json"), separators=(",", ":")).encode(
                "utf-8"
            )
            gz.write(line)
            gz.write(b"\n")

    events_bytes = events_buffer.getvalue()

    with ZipFile(out_path, mode="w", compression=ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_json)
        zf.writestr("summary.json", summary_json)
        zf.writestr("events.ndjson.gz", events_bytes)

    return out_path.resolve()

