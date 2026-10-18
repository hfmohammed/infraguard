"""Deterministic policy remediation proposals."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from infraguard.models import Finding, Resource, SourceType
from infraguard.remediation.models import RemediationProposal


def _pod_spec(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("kind") == "Pod":
        value = manifest.setdefault("spec", {})
        return value if isinstance(value, dict) else {}
    if manifest.get("kind") == "CronJob":
        value = manifest["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        return value if isinstance(value, dict) else {}
    value = manifest["spec"]["template"]["spec"]
    return value if isinstance(value, dict) else {}


def strip_server_fields(manifest: dict[str, Any]) -> dict[str, Any]:
    """Remove fields controlled by the Kubernetes API server."""
    result = copy.deepcopy(manifest)
    result.pop("status", None)
    metadata = result.get("metadata", {})
    for field in ("managedFields", "resourceVersion", "uid", "creationTimestamp", "generation"):
        metadata.pop(field, None)
    return result


def propose(finding: Finding, resource: Resource) -> RemediationProposal:
    """Create a deterministic fix for a supported Kubernetes policy."""
    if resource.ref.source != SourceType.KUBERNETES_LIVE:
        raise ValueError("remediation proposals require a live Kubernetes resource")
    manifest = strip_server_fields(resource.raw)
    spec = _pod_spec(manifest)
    containers = spec.get("containers") or []
    if not containers:
        raise ValueError("target has no containers")
    container = containers[0]
    security = container.setdefault("securityContext", {})
    if finding.policy_id == "K8S-SEC-001":
        security["privileged"] = False
    elif finding.policy_id == "K8S-SEC-002":
        security.update(runAsNonRoot=True, runAsUser=10001)
    elif finding.policy_id == "K8S-SEC-005":
        security["allowPrivilegeEscalation"] = False
    elif finding.policy_id == "K8S-SEC-007":
        security["readOnlyRootFilesystem"] = True
        mounts = container.setdefault("volumeMounts", [])
        volumes = spec.setdefault("volumes", [])
        if not any(item.get("mountPath") == "/tmp" for item in mounts):
            mounts.append({"name": "tmp", "mountPath": "/tmp"})
            volumes.append({"name": "tmp", "emptyDir": {}})
    elif finding.policy_id == "K8S-REL-001":
        container["resources"] = {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"memory": "256Mi"},
        }
    elif finding.policy_id == "K8S-REL-003":
        ports = container.get("ports") or []
        if not ports:
            raise ValueError("probe remediation requires a declared container port")
        probe = {"tcpSocket": {"port": ports[0]["containerPort"]}}
        container["livenessProbe"] = probe
        container["readinessProbe"] = copy.deepcopy(probe)
    else:
        raise ValueError(f"no deterministic remediation for {finding.policy_id}")
    return RemediationProposal(
        proposal_id=str(uuid4()),
        finding_fingerprint=finding.fingerprint,
        policy_id=finding.policy_id,
        target=resource.ref,
        proposed_manifest=manifest,
        rationale=f"Apply the catalog remediation for {finding.policy_id}: {finding.remediation}",
        proposer="rule_based",
        created_at=datetime.now(UTC),
    )
