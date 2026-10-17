from pathlib import Path

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.native import NativePolicyValidator


def validate(resources: list) -> set[str]:
    findings, _ = NativePolicyValidator(PolicyCatalog.load()).validate(resources)
    return {finding.policy_id for finding in findings}


def test_compliant_manifest_has_no_findings() -> None:
    resources = list(ManifestCollector([Path("samples/manifests/compliant")]).collect())
    assert validate(resources) == set()


def test_noncompliant_manifest_covers_every_kubernetes_policy() -> None:
    resources = list(ManifestCollector([Path("samples/manifests/noncompliant")]).collect())
    assert validate(resources) == {
        policy.id for policy in PolicyCatalog.load().all() if policy.target == "kubernetes"
    }


def test_noncompliant_plan_covers_aws_policies() -> None:
    resources = list(
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/noncompliant.plan.fixture.json")
        ).collect()
    )
    identifiers = validate(resources)
    assert {
        "TF-AWS-NET-001",
        "TF-AWS-NET-002",
        "TF-AWS-S3-001",
        "TF-AWS-S3-002",
        "TF-AWS-S3-003",
        "TF-AWS-IAM-001",
    } <= identifiers


def test_destroy_plan_covers_plan_policies() -> None:
    resources = list(
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/destroy.plan.fixture.json")
        ).collect()
    )
    identifiers = validate(resources)
    assert {"TF-PLAN-001", "TF-PLAN-002"} <= identifiers
