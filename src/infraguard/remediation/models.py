"""Models for guarded remediation proposals and outcomes."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from infraguard.models import ResourceRef


class RemediationProposal(BaseModel):
    """A full desired Kubernetes object tied to one finding."""

    model_config = ConfigDict(extra="forbid")
    proposal_id: str
    finding_fingerprint: str
    policy_id: str
    target: ResourceRef
    proposed_manifest: dict[str, Any]
    rationale: str = Field(max_length=2000)
    proposer: Literal["rule_based", "ollama", "external_ai"]
    created_at: datetime


class StepResult(BaseModel):
    """One auditable pipeline decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    step: Literal["schema", "kubeconform", "conftest", "dry_run", "approval", "apply"]
    result: Literal["pass", "fail", "approved", "rejected", "skipped"]
    detail: str | None = None
    duration_ms: float


class PipelineResult(BaseModel):
    """Complete guarded remediation outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    proposal_id: str
    steps: list[StepResult]
    diff: str | None = None
    applied: bool = False
    ownership_transfer: bool = False
