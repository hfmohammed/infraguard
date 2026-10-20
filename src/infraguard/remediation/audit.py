"""Append-only remediation audit logging."""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

from prometheus_client import CollectorRegistry, Counter

from infraguard.remediation.models import RemediationProposal, StepResult

REGISTRY = CollectorRegistry()
PIPELINE = Counter(
    "infraguard_remediation_pipeline_total",
    "Remediation gate outcomes",
    ["step", "result"],
    registry=REGISTRY,
)


def append_step(
    path: Path,
    proposal: RemediationProposal,
    step: StepResult,
    context: str | None = None,
) -> None:
    """Append metadata for one executed step without writing manifest contents."""
    path.parent.mkdir(parents=True, exist_ok=True)
    manifest = json.dumps(proposal.proposed_manifest, sort_keys=True, separators=(",", ":"))
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "proposal_id": proposal.proposal_id,
        "step": step.step,
        "result": step.result,
        "policy_id": proposal.policy_id,
        "target": proposal.target.key(),
        "context": context,
        "actor": f"{getpass.getuser()}@{socket.gethostname()}",
        "proposer": proposal.proposer,
        "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
        "detail": step.detail,
    }
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, sort_keys=True) + "\n")
    PIPELINE.labels(step.step, step.result).inc()
