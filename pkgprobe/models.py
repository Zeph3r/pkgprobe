from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
    version: Optional[str] = None
    version_operator: Optional[str] = None  # "ge" | "eq" | None (presence-only)


class CveResult(BaseModel):
    """Single CVE record from NVD; match_type and match_confidence optional for backward compat."""
    cve_id: str
    summary: str = ""
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    published: Optional[str] = None
    url: str = ""
    match_type: Optional[Literal["cpe", "keyword"]] = None
    match_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)


SilentViability = Literal["unknown", "likely", "unlikely"]
InstallRecommendation = Literal["silent_may_work", "trace_recommended"]
ConfidenceTier = Literal["high", "medium", "low"]
DeploymentRisk = Literal["low", "moderate", "high"]
NextStep = Literal["auto_package", "trace_recommended", "manual_review", "alternate_deployment_path"]
PackagingTier = Literal["simple", "pro", "auto_wrap"]


class FamilyResult(BaseModel):
    """Structured family detection output with evidence and alternatives."""

    family: str
    confidence: float = Field(ge=0.0, le=1.0)
    confidence_tier: ConfidenceTier
    evidence: List[Evidence] = Field(default_factory=list)
    alternatives_considered: List[Dict[str, Any]] = Field(default_factory=list)


class DeploymentAssessment(BaseModel):
    """Operational viability separate from family identification."""

    silent_viability: SilentViability
    deployment_risk: DeploymentRisk
    recommended_next_step: NextStep
    packaging_tier: PackagingTier = "auto_wrap"
    tier_reason: str = ""
    suggested_command: str = ""
    risk_factors: List[str] = Field(default_factory=list)


class InstallPlan(BaseModel):
    input_path: str
    file_type: str  # "msi" | "exe" | "unknown"
    installer_type: str  # "MSI", "Inno Setup", etc.
    confidence: float = Field(ge=0.0, le=1.0)

    metadata: Dict[str, Any] = Field(default_factory=dict)
    """May include structured `preflight` key from EXE analysis (help probe, 7z listing)."""

    family_result: Optional[FamilyResult] = None
    """Structured family detection with evidence trail and rejected alternatives."""

    silent_viability: SilentViability = "unknown"
    """Heuristic: how likely a silent/unattended install is without tracing."""

    recommendation: InstallRecommendation = "silent_may_work"
    """`trace_recommended` when silent is a poor bet — prefer VM trace / repackage."""

    deployment: Optional[DeploymentAssessment] = None
    """Operational viability assessment, separate from family classification."""

    install_candidates: List[CommandCandidate] = Field(default_factory=list)
    uninstall_candidates: List[CommandCandidate] = Field(default_factory=list)

    detection_rules: List[DetectionRule] = Field(default_factory=list)

    notes: List[str] = Field(default_factory=list)

    cve_results: List[CveResult] = Field(default_factory=list)
    cve_check_message: Optional[str] = None  # Set when skipped or NVD unavailable


Sha256Str = Annotated[str, Field(pattern=r"^[a-fA-F0-9]{64}$")]


class InstallerSigner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject: Optional[str] = None
    thumbprint: Optional[str] = None


class TraceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    trace_id: UUID
    installer_sha256: Sha256Str
    installer_file_name: Optional[str] = None
    installer_size_bytes: Optional[int] = Field(default=None, ge=0)
    installer_signer: Optional[InstallerSigner] = None
    timestamp: datetime
    os_version: str
    machine_type: Literal["physical", "vm", "unknown"] = "unknown"
    privacy_profile: Literal["community", "team", "enterprise"]


class TraceAttemptSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_index: int = Field(ge=0)
    switch_string: str
    exit_code: int
    duration_ms: int = Field(ge=0)
    ui_detected: Optional[bool] = None
    success_score: float = Field(ge=0.0, le=1.0)


class MsiexecPivot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: Optional[bool] = None
    msi_sha256: Optional[Sha256Str] = None
    product_code: Optional[str] = None
    msiexec_cmd_hash: Optional[Sha256Str] = None


class UninstallEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: Optional[str] = None
    display_version: Optional[str] = None
    publisher: Optional[str] = None
    uninstall_string: Optional[str] = None
    quiet_uninstall_string: Optional[str] = None
    product_code: Optional[str] = None
    install_location_hash: Optional[Sha256Str] = None


class ServiceAdded(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: Optional[str] = None
    image_path_hash: Optional[Sha256Str] = None
    start_type: Optional[str] = None


class TaskAdded(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_name: Optional[str] = None
    action_path_hash: Optional[Sha256Str] = None


class FileRoot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_type: Literal[
        "program_files",
        "program_files_x86",
        "program_data",
        "user_profile",
        "temp",
        "windows",
    ]
    root_path_hash: Optional[Sha256Str] = None
    exe_hashes: List[Sha256Str] = Field(default_factory=list)


class TraceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempts: List[TraceAttemptSummary] = Field(min_length=1)
    selected_attempt_index: int = Field(ge=0)
    install_success_score: float = Field(ge=0.0, le=1.0)
    msiexec_pivot: Optional[MsiexecPivot] = None
    uninstall_entries: List[UninstallEntry] = Field(default_factory=list)
    services_added: List[ServiceAdded] = Field(default_factory=list)
    tasks_added: List[TaskAdded] = Field(default_factory=list)
    file_roots: List[FileRoot] = Field(default_factory=list)


class TraceEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "process_start",
        "process_exit",
        "file_write",
        "reg_write",
        "service_create",
        "task_create",
        "network_connect",
    ]
    timestamp: datetime

    pid: Optional[int] = Field(default=None, ge=0)
    parent_pid: Optional[int] = Field(default=None, ge=0)

    image_hash: Optional[Sha256Str] = None
    image_path_hash: Optional[Sha256Str] = None
    command_line_hash: Optional[Sha256Str] = None

    path_hash: Optional[Sha256Str] = None
    registry_key_hash: Optional[Sha256Str] = None
    service_name: Optional[str] = None
    task_name: Optional[str] = None

    dest_ip: Optional[str] = None
    dest_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: Optional[Literal["tcp", "udp"]] = None


class TraceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: TraceManifest
    summary: TraceSummary
