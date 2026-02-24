from __future__ import annotations

import gzip
import json
from pathlib import Path
from zipfile import ZipFile

import pytest

from pkgprobe.trace.bundle import write_pkgtrace
from pkgprobe.trace.session import TraceSession, _sha256_file


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def dummy_installer(tmp_path: Path) -> Path:
    """
    Create a tiny dummy 'installer' file for trace-install tests.
    """
    path = tmp_path / "dummy-installer.exe"
    path.write_bytes(b"dummy-installer")
    return path


@pytest.fixture
def generated_pkgtrace(tmp_path: Path, dummy_installer: Path) -> Path:
    """
    Run a no-exec trace session and write a .pkgtrace bundle.
    """
    session = TraceSession(installer_path=dummy_installer, no_exec=True)
    bundle, events = session.run()
    out_path = tmp_path / "trace.pkgtrace"
    return write_pkgtrace(bundle=bundle, events=events, out_path=out_path)


def _load_json_from_zip(bundle_path: Path, member: str) -> dict:
    with ZipFile(bundle_path, "r") as zf:
        with zf.open(member) as f:
            return json.load(f)


def _iter_events_from_zip(bundle_path: Path) -> list[dict]:
    events: list[dict] = []
    with ZipFile(bundle_path, "r") as zf:
        with zf.open("events.ndjson.gz") as f:
            with gzip.GzipFile(fileobj=f, mode="rb") as gz:
                for line in gz:
                    line = line.strip()
                    if not line:
                        continue
                    events.append(json.loads(line))
    return events


def test_sha256_file_matches_hashlib(dummy_installer: Path) -> None:
    from hashlib import sha256

    expected = sha256(dummy_installer.read_bytes()).hexdigest()
    assert _sha256_file(dummy_installer) == expected


def test_manifest_and_summary_schema(project_root: Path, generated_pkgtrace: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")

    schemas_dir = project_root / "schemas"
    manifest_schema_path = schemas_dir / "manifest.schema.json"
    summary_schema_path = schemas_dir / "summary.schema.json"

    if not (manifest_schema_path.is_file() and summary_schema_path.is_file()):
        pytest.skip("manifest/summary JSON Schemas not present in schemas/ directory")

    manifest = _load_json_from_zip(generated_pkgtrace, "manifest.json")
    summary = _load_json_from_zip(generated_pkgtrace, "summary.json")

    manifest_schema = json.loads(manifest_schema_path.read_text(encoding="utf-8"))
    summary_schema = json.loads(summary_schema_path.read_text(encoding="utf-8"))

    jsonschema.validate(instance=manifest, schema=manifest_schema)
    jsonschema.validate(instance=summary, schema=summary_schema)


def test_events_schema_if_present(project_root: Path, generated_pkgtrace: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")

    schema_path = project_root / "schemas" / "event.schema.json"
    if not schema_path.is_file():
        pytest.skip("event JSON Schema not present in schemas/ directory")

    events = _iter_events_from_zip(generated_pkgtrace)
    if not events:
        pytest.skip("no events in bundle; nothing to validate")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    for event in events:
        jsonschema.validate(instance=event, schema=schema)

