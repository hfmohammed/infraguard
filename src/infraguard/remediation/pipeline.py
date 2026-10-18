"""Fail-closed guarded remediation pipeline."""

from __future__ import annotations

import json
from time import perf_counter

from infraguard.models import SourceType
from infraguard.remediation.models import RemediationProposal, StepResult

ALLOWED_APIS = {"apps/v1", "v1", "batch/v1", "networking.k8s.io/v1", "policy/v1"}
DENIED_KINDS = {
    "ClusterRole",
    "ClusterRoleBinding",
    "Role",
    "RoleBinding",
    "Secret",
    "ServiceAccount",
    "Namespace",
    "CustomResourceDefinition",
    "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration",
}
MAX_MANIFEST_BYTES = 256 * 1024


def validate_proposal(proposal: RemediationProposal) -> StepResult:
    """Enforce target binding, API allow-list, denied kinds, and size limit."""
    started = perf_counter()
    manifest = proposal.proposed_manifest
    metadata = manifest.get("metadata") or {}
    errors: list[str] = []
    if proposal.target.source != SourceType.KUBERNETES_LIVE:
        errors.append("target source must be kubernetes_live")
    if manifest.get("kind") != proposal.target.kind:
        errors.append("manifest kind does not match target")
    if metadata.get("name") != proposal.target.name:
        errors.append("manifest name does not match target")
    if metadata.get("namespace", "default") != (proposal.target.namespace or "default"):
        errors.append("manifest namespace does not match target")
    if manifest.get("apiVersion") not in ALLOWED_APIS:
        errors.append("apiVersion is not allowed")
    if manifest.get("kind") in DENIED_KINDS:
        errors.append("kind is denied for remediation")
    if len(json.dumps(manifest).encode()) > MAX_MANIFEST_BYTES:
        errors.append("manifest exceeds 256 KB")
    return StepResult(
        step="schema",
        result="fail" if errors else "pass",
        detail="; ".join(errors) or None,
        duration_ms=(perf_counter() - started) * 1000,
    )


def validate_manifest_size_and_count(manifest_yaml: str) -> None:
    """Apply MCP manifest input limits before parsing."""
    if len(manifest_yaml.encode()) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest input exceeds 256 KB")
    if manifest_yaml.count("\n---") + 1 > 50:
        raise ValueError("manifest input exceeds 50 documents")
