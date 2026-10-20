"""Runtime guarantees that cannot be inferred from policy fixture counts."""

import json
from pathlib import Path
from types import SimpleNamespace
from urllib.request import urlopen

import pytest

from infraguard.collectors.manifests import ManifestCollector
from infraguard.engine import run_scan
from infraguard.mcp_server import server
from infraguard.mcp_server.audit import audited, configure_audit
from infraguard.models import Category, Finding, Severity, ValidatorRun
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.approval import request_approval
from infraguard.remediation.pipeline import _server_side_apply
from infraguard.reporting.metrics import serve_metrics
from infraguard.validators.native import NativePolicyValidator
from infraguard.validators.registry import build_validators


def test_packaged_catalog_is_independent_of_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert len(PolicyCatalog.load()) == 21


def test_full_mode_never_silently_falls_back():
    assert [v.name for v in build_validators(PolicyCatalog.load())] == [
        "kubeconform",
        "conftest",
        "cross_resource",
        "terraform_analyzer",
    ]
    assert [v.name for v in build_validators(PolicyCatalog.load(), offline=True)] == [
        "native_policy"
    ]


def test_metrics_are_available_over_http():
    catalog = PolicyCatalog.load()
    report = run_scan(
        [ManifestCollector([Path("samples/manifests/compliant")])],
        [NativePolicyValidator(catalog)],
        catalog=catalog,
    )
    http, thread = serve_metrics(report, port=0)
    try:
        with urlopen(f"http://127.0.0.1:{http.server_port}/metrics", timeout=3) as response:
            body = response.read().decode()
        assert "infraguard_last_scan_passed 1.0" in body
        assert "infraguard_resources_scanned_total" in body
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=3)


def test_mcp_audit_records_success_and_failure_without_arguments(tmp_path):
    configure_audit(tmp_path)

    @audited
    def sensitive_tool(secret):
        if secret == "reject":
            raise ValueError("bad argument")
        return secret

    sensitive_tool("do-not-log-this-token")
    with pytest.raises(ValueError):
        sensitive_tool("reject")
    content = (tmp_path / "audit/mcp-calls.jsonl").read_text()
    assert "do-not-log-this-token" not in content
    records = [json.loads(line) for line in content.splitlines()]
    assert [r["result"] for r in records] == ["success", "error"]
    assert all(len(r["args_sha256"]) == 64 for r in records)


def test_mcp_schema_errors_are_reported_honestly(tmp_path, monkeypatch):
    server.configure(allowed_root=tmp_path)
    resource = next(iter(ManifestCollector([Path("samples/manifests/compliant")]).collect()))
    finding = Finding.create(
        policy_id="SCHEMA-001",
        title="Invalid schema",
        severity=Severity.HIGH,
        category=Category.SCHEMA,
        resource=resource.ref,
        message="unknown field",
        remediation="remove field",
        validator="kubeconform",
    )
    validator = SimpleNamespace(
        validate=lambda resources: (
            [finding],
            ValidatorRun(name="kubeconform", duration_ms=0, resources_checked=1, findings=1),
        )
    )
    monkeypatch.setattr(server, "build_validators", lambda catalog: [validator])
    result = server.validate_manifest("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\n")
    assert result["schema_valid"] is False
    assert result["schema_errors"] == ["unknown field"]
    assert result["passed"] is False


@pytest.mark.parametrize("answer,expected", [("api", True), ("API", False), ("yes", False)])
def test_approval_requires_exact_resource_name(monkeypatch, answer, expected):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: answer)
    assert request_approval("api") is expected


@pytest.mark.parametrize("dry_run", [True, False])
def test_dynamic_apply_preserves_server_side_contract(monkeypatch, dry_run):
    from datetime import UTC, datetime

    from infraguard.models import ResourceRef, SourceType
    from infraguard.remediation.models import RemediationProposal

    calls = []
    resource = SimpleNamespace(
        patch=lambda **kwargs: calls.append(kwargs) or {"kind": "Deployment"}
    )
    monkeypatch.setattr("infraguard.remediation.pipeline._dynamic_resource", lambda *a: resource)
    item = RemediationProposal(
        proposal_id="test",
        finding_fingerprint="test",
        policy_id="K8S-SEC-001",
        target=ResourceRef(
            source=SourceType.KUBERNETES_LIVE, kind="Deployment", name="api", namespace="prod"
        ),
        proposed_manifest={"apiVersion": "apps/v1", "kind": "Deployment"},
        rationale="test",
        proposer="rule_based",
        created_at=datetime.now(UTC),
    )
    _server_side_apply(item, "kind-infraguard", dry_run=dry_run)
    assert calls[0]["field_manager"] == "infraguard"
    assert calls[0]["content_type"] == "application/apply-patch+yaml"
    assert calls[0].get("dry_run") == ("All" if dry_run else None)
