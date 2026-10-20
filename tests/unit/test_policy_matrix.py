from pathlib import Path

import pytest

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.native import NativePolicyValidator

KUBERNETES_IDS = [
    "K8S-SEC-001",
    "K8S-SEC-002",
    "K8S-SEC-003",
    "K8S-SEC-004",
    "K8S-SEC-005",
    "K8S-SEC-006",
    "K8S-SEC-007",
    "K8S-REL-001",
    "K8S-REL-002",
    "K8S-REL-003",
    "K8S-REL-004",
    "K8S-NET-001",
    "K8S-NET-002",
]

TERRAFORM_IDS = [
    "TF-AWS-NET-001",
    "TF-AWS-NET-002",
    "TF-AWS-S3-001",
    "TF-AWS-S3-002",
    "TF-AWS-S3-003",
    "TF-AWS-IAM-001",
]


@pytest.fixture(scope="module")
def kubernetes_findings():
    resources = list(ManifestCollector([Path("samples/manifests/noncompliant")]).collect())
    return NativePolicyValidator(PolicyCatalog.load()).validate(resources)[0]


@pytest.fixture(scope="module")
def terraform_findings():
    resources = list(
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/noncompliant.plan.fixture.json")
        ).collect()
    )
    return NativePolicyValidator(PolicyCatalog.load()).validate(resources)[0]


@pytest.mark.parametrize("policy_id", KUBERNETES_IDS)
def test_each_kubernetes_policy_has_a_seeded_finding(policy_id, kubernetes_findings) -> None:
    matches = [item for item in kubernetes_findings if item.policy_id == policy_id]
    assert len(matches) == 1
    assert matches[0].path


@pytest.mark.parametrize("policy_id", TERRAFORM_IDS)
def test_each_terraform_policy_has_a_seeded_finding(policy_id, terraform_findings) -> None:
    matches = [item for item in terraform_findings if item.policy_id == policy_id]
    # Both the SSH range and the all-protocol rule expose SSH to the world.
    assert len(matches) == (2 if policy_id == "TF-AWS-NET-001" else 1)
    assert matches[0].resource.address


@pytest.mark.parametrize("policy_id", KUBERNETES_IDS + TERRAFORM_IDS)
def test_every_policy_has_actionable_metadata(policy_id) -> None:
    policy = PolicyCatalog.load().get(policy_id)
    assert policy.title
    assert len(policy.remediation) >= 10
    assert Path(policy.fixture).exists()
