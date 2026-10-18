"""Read-only Model Context Protocol server."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Literal, cast

import yaml
from mcp.server.fastmcp import FastMCP

from infraguard.collectors.kubernetes_live import KubernetesLiveCollector
from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.mcp_server.readonly import guarded_path
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.pipeline import validate_manifest_size_and_count
from infraguard.validators.native import NativePolicyValidator

mcp = FastMCP("infraguard")
_allowed_root = Path.cwd()
_context: str | None = None


def configure(*, allowed_root: Path | None = None, context: str | None = None) -> None:
    """Configure server path and cluster boundaries before starting transport."""
    global _allowed_root, _context
    _allowed_root = (allowed_root or Path.cwd()).resolve()
    _context = context


def _resources(kind: str | None = None, namespace: str | None = None) -> list[Any]:
    resources = list(
        KubernetesLiveCollector(_context, [namespace] if namespace else None).collect()
    )
    return [
        resource
        for resource in resources
        if kind is None or resource.ref.kind.lower() == kind.lower()
    ]


@mcp.tool()
def list_cluster_resources(
    kind: str | None = None, namespace: str | None = None, limit: int = 100
) -> list[dict[str, Any]]:
    """List normalized resource refs and labels from the live cluster."""
    capped = max(0, min(limit, 500))
    return [
        {"ref": resource.ref.model_dump(mode="json"), "labels": resource.labels}
        for resource in _resources(kind, namespace)[:capped]
    ]


@mcp.tool()
def get_resource(kind: str, name: str, namespace: str | None = None) -> dict[str, Any]:
    """Return one redacted live manifest."""
    for resource in _resources(kind, namespace):
        if resource.ref.name == name:
            return cast(dict[str, Any], resource.raw)
    raise ValueError(f"resource not found: {kind}/{name}")


@mcp.tool()
def get_policy_findings(
    severity: str | None = None,
    policy_id: str | None = None,
    namespace: str | None = None,
    report_path: str | None = None,
) -> dict[str, Any]:
    """Read findings from a guarded report path or run a fresh read-only scan."""
    if report_path:
        from infraguard.models import ScanReport

        report = ScanReport.model_validate_json(
            guarded_path(report_path, _allowed_root).read_text()
        )
        findings = report.findings
        summary = report.summary.model_dump(mode="json")
    else:
        resources = _resources(namespace=namespace)
        catalog = PolicyCatalog.load(_allowed_root / "policies" / "metadata.yaml")
        findings, _ = NativePolicyValidator(catalog).validate(resources)
        summary = {"findings_total": len(findings), "resources_scanned": len(resources)}
    selected = [
        finding.model_dump(mode="json")
        for finding in findings
        if (severity is None or finding.severity.value == severity.upper())
        and (policy_id is None or finding.policy_id == policy_id)
        and (namespace is None or finding.resource.namespace == namespace)
    ]
    return {"summary": summary, "findings": selected}


@mcp.tool()
def analyze_terraform_plan(plan_json_path: str) -> dict[str, Any]:
    """Analyze an existing plan inside the allowed root without running Terraform."""
    path = guarded_path(plan_json_path, _allowed_root)
    resources = list(TerraformPlanCollector(plan_json=path).collect())
    findings, _ = NativePolicyValidator(
        PolicyCatalog.load(_allowed_root / "policies" / "metadata.yaml")
    ).validate(resources)
    changes = {"create": 0, "update": 0, "delete": 0, "replace": 0}
    for resource in resources:
        actions = resource.raw.get("change", {}).get("actions", [])
        if "delete" in actions and "create" in actions:
            changes["replace"] += 1
        else:
            for action in changes:
                if action in actions:
                    changes[action] += 1
    return {"changes": changes, "findings": [item.model_dump(mode="json") for item in findings]}


@mcp.tool()
def validate_manifest(manifest_yaml: str) -> dict[str, Any]:
    """Validate supplied YAML with the deterministic policy catalog."""
    validate_manifest_size_and_count(manifest_yaml)
    list(yaml.safe_load_all(manifest_yaml))  # fail early on malformed YAML
    with tempfile.TemporaryDirectory(prefix="infraguard-mcp-") as temporary:
        source = Path(temporary) / "input.yaml"
        source.write_text(manifest_yaml)
        resources = list(ManifestCollector([source]).collect())
    findings, _ = NativePolicyValidator(
        PolicyCatalog.load(_allowed_root / "policies" / "metadata.yaml")
    ).validate(resources)
    return {
        "schema_valid": True,
        "schema_errors": [],
        "findings": [finding.model_dump(mode="json") for finding in findings],
        "passed": not findings,
    }


@mcp.tool()
def validate_patch(
    target_kind: str,
    target_name: str,
    namespace: str,
    patched_manifest_yaml: str,
) -> dict[str, Any]:
    """Validate a proposed full manifest without applying it."""
    result = cast(dict[str, Any], validate_manifest(patched_manifest_yaml))
    documents = [
        item for item in yaml.safe_load_all(patched_manifest_yaml) if isinstance(item, dict)
    ]
    target_matches = (
        len(documents) == 1
        and documents[0].get("kind") == target_kind
        and documents[0].get("metadata", {}).get("name") == target_name
        and documents[0].get("metadata", {}).get("namespace", "default") == namespace
    )
    result.update(
        applied=False,
        target_matches=target_matches,
        next_step="a human must run `infraguard remediate apply` and approve",
    )
    result["passed"] = bool(result["passed"] and target_matches)
    return result


def serve(transport: Literal["stdio", "sse", "streamable-http"] = "stdio") -> None:
    """Run the MCP server on the selected transport."""
    mcp.run(transport=transport)
