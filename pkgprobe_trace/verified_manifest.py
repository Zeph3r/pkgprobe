"""
Verified trace manifest
----------------------

This manifest is produced from a completed trace + diff and is meant to be
stable, portable, and cloud-worker friendly.

It captures:
- the *best known* silent install command (as arguments) that was executed
- a set of detection candidates derived from observed system changes

The manifest is used downstream for packaging outputs like `.intunewin`.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional


DetectionType = Literal[
    "registry_key",
    "registry_value",
    "file_exists",
    "service_exists",
    "scheduled_task_exists",
    "msi_product_code",
]


@dataclass(frozen=True)
class DetectionCandidate:
    type: DetectionType
    value: str
    confidence: float = 0.5
    rationale: str = ""
    version: str = ""
    version_operator: str = ""  # "ge" | "eq" | "" (presence-only)


@dataclass(frozen=True)
class VerifiedTraceManifest:
    schema_version: str = "v1"
    installer_filename: str = ""
    install_exe_name: str = ""
    silent_args: List[str] = field(default_factory=list)
    detection_candidates: List[DetectionCandidate] = field(default_factory=list)
    verified: bool = False
    verification_errors: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # draft=True: local OSS preview only; authoritative verification is api.pkgprobe.io
    draft: bool = True
    verification_authority: str = "local_draft"
    product_version: str = ""
    product_code: str = ""

    def to_json_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "installer_filename": self.installer_filename,
            "install_exe_name": self.install_exe_name,
            "silent_args": list(self.silent_args),
            "detection_candidates": [asdict(x) for x in self.detection_candidates],
            "verified": self.verified,
            "verification_errors": list(self.verification_errors),
            "notes": list(self.notes),
            "draft": self.draft,
            "verification_authority": self.verification_authority,
            "product_version": self.product_version,
            "product_code": self.product_code,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_json_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_json(cls, raw: str) -> "VerifiedTraceManifest":
        d = json.loads(raw)
        candidates = [
            DetectionCandidate(**c) for c in (d.get("detection_candidates") or [])
        ]
        verified = bool(d.get("verified", False))
        if "draft" in d:
            draft = bool(d.get("draft"))
        else:
            draft = not verified
        return cls(
            schema_version=d.get("schema_version", "v1"),
            installer_filename=d.get("installer_filename", ""),
            install_exe_name=d.get("install_exe_name", ""),
            silent_args=list(d.get("silent_args") or []),
            detection_candidates=candidates,
            verified=verified,
            verification_errors=list(d.get("verification_errors") or []),
            notes=list(d.get("notes") or []),
            draft=draft,
            verification_authority=str(d.get("verification_authority") or ("local_draft" if draft else "legacy_local")),
            product_version=str(d.get("product_version") or ""),
            product_code=str(d.get("product_code") or ""),
        )

