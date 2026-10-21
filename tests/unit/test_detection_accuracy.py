"""Exact seeded detection accounting, including incidental expected findings."""

from pathlib import Path

import yaml

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.native import NativePolicyValidator


def test_seeded_precision_recall_and_catalog_coverage():
    resources = list(ManifestCollector([Path("samples/manifests/noncompliant")]).collect())
    for name in ("noncompliant", "destroy"):
        resources.extend(
            TerraformPlanCollector(
                plan_json=Path(f"samples/terraform/plan-fixtures/{name}.plan.fixture.json")
            ).collect()
        )
    catalog = PolicyCatalog.load()
    findings, _ = NativePolicyValidator(catalog).validate(resources)
    expected = {
        (row["policy_id"], row["resource_key"])
        for row in yaml.safe_load(Path("tests/golden/expected_violations.yaml").read_text())
    }
    actual = {(finding.policy_id, finding.resource.key()) for finding in findings}
    assert actual == expected
    assert {finding.policy_id for finding in findings} == {policy.id for policy in catalog.all()}
    assert len(findings) == len(expected)
