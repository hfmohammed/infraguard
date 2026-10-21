"""Fail-closed guarded remediation pipeline."""

from __future__ import annotations

import difflib
import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any

import yaml
from kubernetes import client, config, dynamic
from kubernetes.config.config_exception import ConfigException
from kubernetes.dynamic.resource import ResourceInstance

from infraguard.collectors.kubernetes_live import KubernetesLiveCollector
from infraguard.errors import InfraGuardError
from infraguard.mcp_server.readonly import ReadOnlyK8s
from infraguard.models import Resource, ResourceRef, SourceType
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.approval import request_approval
from infraguard.remediation.audit import append_step
from infraguard.remediation.models import PipelineResult, RemediationProposal, StepResult
from infraguard.remediation.proposer import strip_server_fields
from infraguard.validators.conftest import ConftestValidator
from infraguard.validators.kubeconform import KubeconformValidator

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
    if not isinstance(metadata, dict):
        return StepResult(
            step="schema", result="fail", detail="metadata must be an object", duration_ms=0
        )
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
    if "***REDACTED***" in json.dumps(manifest):
        errors.append("redacted values cannot be applied; supply an unredacted local proposal")
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
    for index, _ in enumerate(yaml.safe_load_all(manifest_yaml), start=1):
        if index > 50:
            raise ValueError("manifest input exceeds 50 documents")


def _proposal_resource(proposal: RemediationProposal) -> Resource:
    """Convert a proposal manifest to the validator's normalized model."""
    metadata = proposal.proposed_manifest.get("metadata") or {}
    return Resource(
        ref=ResourceRef(
            source=SourceType.KUBERNETES_LIVE,
            kind=proposal.target.kind,
            name=proposal.target.name,
            namespace=proposal.target.namespace,
            api_version=str(proposal.proposed_manifest.get("apiVersion", "")),
        ),
        labels=metadata.get("labels") or {},
        annotations=metadata.get("annotations") or {},
        raw=proposal.proposed_manifest,
        collected_at=datetime.now(UTC),
    )


def _find_live_resource(proposal: RemediationProposal, context: str | None) -> Resource:
    resources = KubernetesLiveCollector(
        context=context,
        namespaces=[proposal.target.namespace] if proposal.target.namespace else None,
    ).collect()
    for resource in resources:
        if (
            resource.ref.kind == proposal.target.kind
            and resource.ref.name == proposal.target.name
            and resource.ref.namespace == proposal.target.namespace
        ):
            return resource
    raise ValueError(f"live target was not found: {proposal.target.key()}")


def _dynamic_resource(proposal: RemediationProposal, context: str | None) -> Any:
    try:
        config.load_kube_config(context=context)
    except ConfigException:
        if context is not None:
            raise
        config.load_incluster_config()
    api = dynamic.DynamicClient(client.ApiClient())
    return api.resources.get(
        api_version=str(proposal.proposed_manifest["apiVersion"]),
        kind=proposal.target.kind,
    )


def _server_side_apply(
    proposal: RemediationProposal,
    context: str | None,
    *,
    dry_run: bool,
    take_ownership: bool = False,
) -> dict[str, Any]:
    resource = _dynamic_resource(proposal, context)
    kwargs: dict[str, Any] = {
        "name": proposal.target.name,
        "body": proposal.proposed_manifest,
        "content_type": "application/apply-patch+yaml",
        "field_manager": "infraguard",
    }
    if proposal.target.namespace:
        kwargs["namespace"] = proposal.target.namespace
    if take_ownership:
        kwargs["force_conflicts"] = True
    if dry_run:
        response = ReadOnlyK8s(resource).dry_run_apply("patch", **kwargs)
    else:
        response = resource.patch(**kwargs)
    serialized = (
        response.to_dict()
        if isinstance(response, ResourceInstance)
        else client.ApiClient().sanitize_for_serialization(response)
    )
    if not isinstance(serialized, dict):
        raise TypeError("Kubernetes returned a non-object response")
    return serialized


def _diff(live: Resource, desired: dict[str, Any]) -> str:
    before = yaml.safe_dump(strip_server_fields(live.raw), sort_keys=True).splitlines()
    after = yaml.safe_dump(strip_server_fields(desired), sort_keys=True).splitlines()
    return "\n".join(
        difflib.unified_diff(before, after, fromfile="live", tofile="proposed", lineterm="")
    )


def check_proposal(
    proposal: RemediationProposal,
    *,
    context: str | None = None,
    catalog: PolicyCatalog | None = None,
    audit_path: Path = Path("audit/remediation.jsonl"),
    take_ownership: bool = False,
) -> PipelineResult:
    """Run schema, kubeconform, policy, and server-side dry-run gates."""
    catalog = catalog or PolicyCatalog.load()
    steps: list[StepResult] = []

    schema = validate_proposal(proposal)
    steps.append(schema)
    append_step(audit_path, proposal, schema, context)
    if schema.result == "fail":
        return PipelineResult(proposal_id=proposal.proposal_id, steps=steps, applied=False)

    proposed = _proposal_resource(proposal)
    started = perf_counter()
    try:
        schema_findings, _ = KubeconformValidator().validate([proposed])
        kubeconform = StepResult(
            step="kubeconform",
            result="fail" if schema_findings else "pass",
            detail=schema_findings[0].message if schema_findings else None,
            duration_ms=(perf_counter() - started) * 1000,
        )
    except InfraGuardError as error:
        kubeconform = StepResult(
            step="kubeconform",
            result="fail",
            detail=str(error),
            duration_ms=(perf_counter() - started) * 1000,
        )
    steps.append(kubeconform)
    append_step(audit_path, proposal, kubeconform, context)
    if kubeconform.result == "fail":
        return PipelineResult(proposal_id=proposal.proposal_id, steps=steps, applied=False)

    try:
        live = _find_live_resource(proposal, context)
        policy_validator = ConftestValidator(catalog)
        live_findings, _ = policy_validator.validate([live])
        proposed_findings, _ = policy_validator.validate([proposed])
    except (InfraGuardError, ValueError) as error:
        failure = StepResult(step="conftest", result="fail", detail=str(error), duration_ms=0)
        append_step(audit_path, proposal, failure, context)
        return PipelineResult(proposal_id=proposal.proposal_id, steps=[*steps, failure])
    live_keys = {(finding.policy_id, finding.path) for finding in live_findings}
    proposed_keys = {(finding.policy_id, finding.path) for finding in proposed_findings}
    new_findings = proposed_keys - live_keys
    target_remains = any(finding.policy_id == proposal.policy_id for finding in proposed_findings)
    policy_passed = not target_remains and not new_findings
    policy = StepResult(
        step="conftest",
        result="pass" if policy_passed else "fail",
        detail=(
            None
            if policy_passed
            else f"target_remains={target_remains}; new_findings={sorted(new_findings)}"
        ),
        duration_ms=0,
    )
    steps.append(policy)
    append_step(audit_path, proposal, policy, context)
    if policy.result == "fail":
        return PipelineResult(proposal_id=proposal.proposal_id, steps=steps, applied=False)

    started = perf_counter()
    try:
        dry_run_object = _server_side_apply(
            proposal, context, dry_run=True, take_ownership=take_ownership
        )
        dry_run = StepResult(
            step="dry_run",
            result="pass",
            detail="field ownership transfer requested" if take_ownership else None,
            duration_ms=(perf_counter() - started) * 1000,
        )
    except Exception as error:
        dry_run_object = proposal.proposed_manifest
        dry_run = StepResult(
            step="dry_run",
            result="fail",
            detail=str(error),
            duration_ms=(perf_counter() - started) * 1000,
        )
    steps.append(dry_run)
    append_step(audit_path, proposal, dry_run, context)
    return PipelineResult(
        proposal_id=proposal.proposal_id,
        steps=steps,
        diff=_diff(live, dry_run_object),
        applied=False,
        ownership_transfer=take_ownership,
    )


def apply_proposal(
    proposal: RemediationProposal,
    *,
    context: str | None = None,
    catalog: PolicyCatalog | None = None,
    audit_path: Path = Path("audit/remediation.jsonl"),
    take_ownership: bool = False,
) -> PipelineResult:
    """Run all gates, request interactive approval, then perform server-side apply."""
    checked = check_proposal(
        proposal,
        context=context,
        catalog=catalog,
        audit_path=audit_path,
        take_ownership=take_ownership,
    )
    if any(step.result == "fail" for step in checked.steps):
        return checked

    started = perf_counter()
    print_approval_summary(proposal, checked, context)
    try:
        approved = request_approval(proposal.target.name)
    except RuntimeError as error:
        append_step(
            audit_path,
            proposal,
            StepResult(
                step="approval",
                result="rejected",
                detail=str(error),
                duration_ms=0,
            ),
            context,
        )
        raise
    approval = StepResult(
        step="approval",
        result="approved" if approved else "rejected",
        duration_ms=(perf_counter() - started) * 1000,
    )
    steps = [*checked.steps, approval]
    append_step(audit_path, proposal, approval, context)
    if not approved:
        return checked.model_copy(update={"steps": steps})

    started = perf_counter()
    try:
        _server_side_apply(proposal, context, dry_run=False, take_ownership=take_ownership)
        applied = StepResult(
            step="apply",
            result="pass",
            duration_ms=(perf_counter() - started) * 1000,
        )
    except Exception as error:
        applied = StepResult(
            step="apply",
            result="fail",
            detail=str(error),
            duration_ms=(perf_counter() - started) * 1000,
        )
    steps.append(applied)
    append_step(audit_path, proposal, applied, context)
    return checked.model_copy(update={"steps": steps, "applied": applied.result == "pass"})


def print_approval_summary(
    proposal: RemediationProposal, checked: PipelineResult, context: str | None
) -> None:
    """Show the exact checked change before requesting interactive approval."""
    from rich.console import Console
    from rich.syntax import Syntax

    console = Console()
    console.print("InfraGuard remediation approval", style="bold")
    for label, value in (
        ("Proposal", proposal.proposal_id),
        ("Proposer", proposal.proposer),
        ("Policy", proposal.policy_id),
        ("Target", proposal.target.key()),
        ("Context", context or "current"),
        ("Rationale", proposal.rationale),
        (
            "Field ownership",
            "transfer conflicting fields"
            if checked.ownership_transfer
            else "preserve existing owners",
        ),
    ):
        console.print(f"{label}: {value}", markup=False)
    console.print(
        "Checks: " + ", ".join(f"{s.step}={s.result}" for s in checked.steps), markup=False
    )
    console.print(Syntax(checked.diff or "(no changes)", "diff", word_wrap=True))
