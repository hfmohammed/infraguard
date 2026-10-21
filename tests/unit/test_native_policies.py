import json
from pathlib import Path

import pytest

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


@pytest.mark.parametrize(
    "kind,after,expected",
    [
        (
            "aws_security_group_rule",
            {
                "type": "ingress",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "ipv6_cidr_blocks": ["::/0"],
            },
            "TF-AWS-NET-001",
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv6": "::/0"},
            "TF-AWS-NET-001",
        ),
        (
            "aws_iam_role_policy",
            {
                "policy": json.dumps(
                    {"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}
                )
            },
            "TF-AWS-IAM-001",
        ),
        ("aws_s3_bucket_acl", {"acl": "public-read"}, "TF-AWS-S3-001"),
        ("aws_s3_bucket_public_access_block", {"block_public_acls": False}, "TF-AWS-S3-001"),
    ],
)
def test_alternate_aws_resource_shapes(tmp_path, kind, after, expected):
    path = tmp_path / "fixture.json"
    path.write_text(
        json.dumps(
            {
                "resource_changes": [
                    {
                        "address": f"{kind}.example",
                        "type": kind,
                        "name": "example",
                        "change": {"actions": ["create"], "after": after},
                    }
                ]
            }
        )
    )
    resources = list(TerraformPlanCollector(plan_json=path).collect())
    assert expected in validate(resources)
