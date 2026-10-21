"""Exercise the public workflows against a real API server and real validators."""

import copy
import json
from pathlib import Path

import pytest
import yaml
from kubernetes import client, config
from typer.testing import CliRunner

from infraguard.cli import app
from infraguard.collectors.kubernetes_live import KubernetesLiveCollector
from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.engine import run_scan
from infraguard.mcp_server import server
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.models import RemediationProposal
from infraguard.remediation.pipeline import check_proposal
from infraguard.validators.registry import build_validators

pytestmark = pytest.mark.integration


def test_full_validator_stack_matches_expected_inventory(cluster_context):
    catalog = PolicyCatalog.load()
    collectors = [ManifestCollector([Path("samples/manifests/noncompliant")])]
    collectors.extend(
        TerraformPlanCollector(
            plan_json=Path(f"samples/terraform/plan-fixtures/{name}.plan.fixture.json")
        )
        for name in ("noncompliant", "destroy")
    )
    report = run_scan(collectors, build_validators(catalog), catalog=catalog)
    expected = {
        (row["policy_id"], row["resource_key"])
        for row in yaml.safe_load(Path("tests/golden/expected_violations.yaml").read_text())
    }
    assert {(f.policy_id, f.resource.key()) for f in report.findings} == expected
    assert len(report.findings) == len(expected)


def live_deployment(context):
    config.load_kube_config(context=context)
    return client.AppsV1Api().read_namespaced_deployment("vulnerable-app", "ig-noncompliant")


def test_live_policy_accuracy(cluster_context):
    catalog = PolicyCatalog.load()
    clean = run_scan(
        [KubernetesLiveCollector(cluster_context, ["ig-compliant"])],
        build_validators(catalog),
        catalog=catalog,
    )
    assert clean.findings == []
    vulnerable = run_scan(
        [KubernetesLiveCollector(cluster_context, ["ig-noncompliant"])],
        build_validators(catalog),
        catalog=catalog,
    )
    expected = {p.id for p in catalog.all() if p.target == "kubernetes"}
    assert {f.policy_id for f in vulnerable.findings} == expected
    assert vulnerable.summary.passed is False


@pytest.mark.parametrize(
    "fixture,failed_step",
    [
        ("good-patch.yaml", None),
        ("bad-patches/01-retarget.yaml", "schema"),
        ("bad-patches/01-denied-kind.yaml", "schema"),
        ("bad-patches/02-invalid-field.yaml", "kubeconform"),
        ("bad-patches/03-new-violation.yaml", "conftest"),
        ("bad-patches/04-immutable-selector.yaml", "dry_run"),
    ],
)
def test_remediation_stops_at_expected_gate(cluster_context, fixture, failed_step, tmp_path):
    before = live_deployment(cluster_context).metadata.resource_version
    proposal = RemediationProposal.model_validate(
        yaml.safe_load((Path("samples/remediation") / fixture).read_text())
    )
    result = check_proposal(
        proposal, context=cluster_context, audit_path=tmp_path / "audit.jsonl", take_ownership=True
    )
    failures = [s.step for s in result.steps if s.result == "fail"]
    assert failures == ([failed_step] if failed_step else []), result.model_dump_json()
    if failed_step:
        assert result.steps[-1].step == failed_step
        if failed_step == "dry_run":
            assert "immutable" in (result.steps[-1].detail or "").lower()
    else:
        assert len(result.steps) == 4
        assert "privileged" in result.diff
    assert result.applied is False
    assert live_deployment(cluster_context).metadata.resource_version == before
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [line["step"] for line in lines] == [s.step for s in result.steps]


def test_six_mcp_tools_against_kind_without_mutation(cluster_context, tmp_path):
    server.configure(allowed_root=Path.cwd(), context=cluster_context)
    before = live_deployment(cluster_context).metadata.resource_version
    assert (
        server.list_cluster_resources("Deployment", "ig-compliant")[0]["ref"]["name"]
        == "compliant-app"
    )
    resource = server.get_resource("Deployment", "vulnerable-app", "ig-noncompliant")
    assert resource["kind"] == "Deployment"
    result = server.get_policy_findings(policy_id="K8S-SEC-001", namespace="ig-noncompliant")
    assert len(result["findings"]) == 1
    plan = server.analyze_terraform_plan(
        "samples/terraform/plan-fixtures/destroy.plan.fixture.json"
    )
    assert plan["changes"]["replace"] == 1
    assert server.validate_manifest(Path("samples/manifests/compliant/app.yaml").read_text())[
        "passed"
    ]
    patch = copy.deepcopy(resource)
    patch["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = False
    from infraguard.remediation.proposer import strip_server_fields

    validated = server.validate_patch(
        "Deployment",
        "vulnerable-app",
        "ig-noncompliant",
        yaml.safe_dump(strip_server_fields(patch)),
    )
    assert validated["passed"] is True
    assert validated["applied"] is False
    assert len(validated["steps"]) == 4
    assert live_deployment(cluster_context).metadata.resource_version == before


def test_cli_refuses_noninteractive_apply_after_real_checks(cluster_context):
    before = live_deployment(cluster_context).metadata.resource_version
    result = CliRunner().invoke(
        app,
        [
            "remediate",
            "apply",
            "samples/remediation/good-patch.yaml",
            "--context",
            cluster_context,
            "--take-ownership",
        ],
    )
    assert result.exit_code == 4, result.stdout
    assert "interactive terminal" in result.stdout
    assert live_deployment(cluster_context).metadata.resource_version == before


def test_helm_field_ownership_is_preserved_by_default(cluster_context, tmp_path):
    proposal = RemediationProposal.model_validate(
        yaml.safe_load(Path("samples/remediation/good-patch.yaml").read_text())
    )
    before = live_deployment(cluster_context).metadata.resource_version
    checked = check_proposal(proposal, context=cluster_context, audit_path=tmp_path / "audit.jsonl")
    assert checked.steps[-1].step == "dry_run"
    assert checked.steps[-1].result == "fail"
    assert "conflict" in checked.steps[-1].detail.lower()
    assert live_deployment(cluster_context).metadata.resource_version == before
