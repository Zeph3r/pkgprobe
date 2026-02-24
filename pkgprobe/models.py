from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Evidence(BaseModel):
    kind: str
    detail: str


class CommandCandidate(BaseModel):
    command: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[Evidence] = Field(default_factory=list)


class DetectionRule(BaseModel):
    kind: str  # e.g. "msi_product_code", "registry_key", "file_exists"
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[Evidence] = Field(default_factory=list)


class InstallPlan(BaseModel):
    input_path: str
    file_type: str  # "msi" | "exe" | "unknown"
    installer_type: str  # "MSI", "Inno Setup", etc.
    confidence: float = Field(ge=0.0, le=1.0)

    metadata: Dict[str, Any] = Field(default_factory=dict)

    install_candidates: List[CommandCandidate] = Field(default_factory=list)
    uninstall_candidates: List[CommandCandidate] = Field(default_factory=list)

    detection_rules: List[DetectionRule] = Field(default_factory=list)

    notes: List[str] = Field(default_factory=list)
