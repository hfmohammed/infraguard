"""Contract tests for Conftest's JSON protocol and resource attribution."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.errors import PolicyCatalogError, ToolError
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.conftest import ConftestValidator


@pytest.mark.parametrize("policy_id", ["K8S-SEC-001", "UNKNOWN-001"])
def test_structured_findings_and_unknown_ids(monkeypatch, policy_id):
    resources = list(ManifestCollector([Path("samples/manifests/noncompliant")]).collect())

    def conftest(command, **kwargs):
        assert "--all-namespaces" in command
        assert kwargs["ok_codes"] == (0, 1)
        source = command[-2]
        assert json.loads(Path(source).read_text())["kind"] == "Deployment"
        return SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "filename": source,
                        "namespace": "infraguard.kubernetes",
                        "failures": [
                            {
                                "msg": json.dumps(
                                    {"id": policy_id, "msg": "privileged", "path": "spec"}
                                )
                            }
                        ],
                    }
                ]
            )
        )

    monkeypatch.setattr("infraguard.validators.conftest.run", conftest)
    validator = ConftestValidator(PolicyCatalog.load())
    if policy_id == "UNKNOWN-001":
        with pytest.raises(PolicyCatalogError, match="unknown policy"):
            validator.validate(resources)
    else:
        findings, execution = validator.validate(resources)
        assert findings[0].resource == resources[0].ref
        assert findings[0].severity.value == "CRITICAL"
        assert execution.findings == 1


def test_terraform_keeps_related_changes_together(monkeypatch):
    resources = list(
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/noncompliant.plan.fixture.json")
        ).collect()
    )

    def conftest(command, **kwargs):
        source = command[-1]
        assert len(json.loads(Path(source).read_text())["resource_changes"]) == len(resources)
        return SimpleNamespace(
            stdout=json.dumps(
                [
                    {
                        "filename": source,
                        "failures": [
                            {
                                "msg": json.dumps(
                                    {
                                        "id": "TF-AWS-S3-002",
                                        "msg": "encryption missing",
                                        "path": "change.after",
                                        "resource": "aws_s3_bucket.raw_logs",
                                    }
                                )
                            }
                        ],
                    }
                ]
            )
        )

    monkeypatch.setattr("infraguard.validators.conftest.run", conftest)
    findings, _ = ConftestValidator(PolicyCatalog.load()).validate(resources)
    assert findings[0].resource.address == "aws_s3_bucket.raw_logs"


def test_invalid_tool_response_is_an_operational_failure(monkeypatch):
    resources = list(ManifestCollector([Path("samples/manifests/compliant")]).collect())
    monkeypatch.setattr(
        "infraguard.validators.conftest.run", lambda *a, **k: SimpleNamespace(stdout="not json")
    )
    with pytest.raises(ToolError, match="invalid Conftest"):
        ConftestValidator(PolicyCatalog.load()).validate(resources)


def test_no_resources_does_not_invoke_a_tool(monkeypatch):
    monkeypatch.setattr(
        "infraguard.validators.conftest.run", lambda *a, **k: pytest.fail("unexpected invocation")
    )
    assert ConftestValidator(PolicyCatalog.load()).validate([])[0] == []
