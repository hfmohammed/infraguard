"""Immutable public data models shared by collectors, validators and reports."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    """Strict immutable base model."""

    model_config = ConfigDict(frozen=True, extra="forbid")


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Return numeric rank used for sorting and thresholds."""
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class SourceType(StrEnum):
    KUBERNETES_LIVE = "kubernetes_live"
    MANIFEST = "manifest"
    TERRAFORM_PLAN = "terraform_plan"
    AWS = "aws"
    GCP = "gcp"


class Category(StrEnum):
    SECURITY = "security"
    RELIABILITY = "reliability"
    NETWORK = "network"
    CHANGE_RISK = "change_risk"
    SCHEMA = "schema"


class ResourceRef(FrozenModel):
    """Stable identity of a normalized resource."""

    source: SourceType
    kind: str
    name: str
    namespace: str | None = None
    api_version: str | None = None
    address: str | None = None
    file: str | None = None

    def key(self) -> str:
        """Return source-independent key used for ordering and deduplication."""
        if self.address:
            return self.address
        return f"{self.namespace or '_cluster'}/{self.kind}/{self.name}"


class Resource(FrozenModel):
    """Normalized resource handed to validators."""

    ref: ResourceRef
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    raw: dict[str, Any]
    collected_at: datetime


class TerraformChange(FrozenModel):
    address: str
    type: str
    name: str
    actions: list[Literal["no-op", "create", "read", "update", "delete"]]
    before: dict[str, Any] | None
    after: dict[str, Any] | None

    @property
    def is_replace(self) -> bool:
        """Return whether the action deletes and recreates the resource."""
        return "delete" in self.actions and "create" in self.actions


class Finding(FrozenModel):
    policy_id: str
    title: str
    severity: Severity
    category: Category
    resource: ResourceRef
    message: str
    remediation: str
    path: str | None = None
    validator: Literal["conftest", "kubeconform", "terraform_analyzer", "python"]
    fingerprint: str

    @classmethod
    def create(cls, **values: Any) -> Finding:
        """Build a finding with its deterministic fingerprint."""
        ref: ResourceRef = values["resource"]
        basis = f"{values['policy_id']}{ref.key()}{values.get('path') or ''}"
        values["fingerprint"] = hashlib.sha256(basis.encode()).hexdigest()[:16]
        return cls(**values)


class ValidatorRun(FrozenModel):
    name: str
    tool_version: str | None = None
    duration_ms: float
    resources_checked: int
    findings: int
    error: str | None = None


class SeveritySummary(FrozenModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class ScanSummary(FrozenModel):
    resources_scanned: int
    resources_by_source: dict[str, int]
    resources_by_kind: dict[str, dict[str, int]] = Field(default_factory=dict)
    findings_total: int
    by_severity: SeveritySummary
    by_policy: dict[str, int]
    policies_evaluated: int
    passed: bool


class ScanReport(FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    tool: Literal["infraguard"] = "infraguard"
    tool_version: str
    scan_id: str
    started_at: datetime
    finished_at: datetime
    duration_ms: float
    phase_durations_ms: dict[str, float] = Field(default_factory=dict)
    targets: list[str]
    fail_on: Severity | Literal["NONE"]
    summary: ScanSummary
    findings: list[Finding]
    validators: list[ValidatorRun]
    errors: list[str] = Field(default_factory=list)


class PolicyMeta(FrozenModel):
    id: str
    title: str
    severity: Severity
    category: Category
    target: Literal["kubernetes", "terraform"]
    engine: Literal["conftest", "terraform_analyzer", "python"]
    description: str
    remediation: str
    fixture: str
