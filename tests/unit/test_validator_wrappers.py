import json
from pathlib import Path
from types import SimpleNamespace

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.cross_resource import CrossResourceValidator
from infraguard.validators.kubeconform import KubeconformValidator
from infraguard.validators.terraform_analyzer import TerraformPlanAnalyzer


def test_cross_resource_wrapper_filters_network_policy() -> None:
    resources = list(ManifestCollector([Path("samples/manifests/noncompliant")]).collect())
    findings, run = CrossResourceValidator(PolicyCatalog.load()).validate(resources)
    assert [item.policy_id for item in findings] == ["K8S-NET-002"]
    assert run.name == "cross_resource"


def test_terraform_analyzer_filters_destructive_changes() -> None:
    resources = list(
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/destroy.plan.fixture.json")
        ).collect()
    )
    findings, run = TerraformPlanAnalyzer(PolicyCatalog.load()).validate(resources)
    assert {item.policy_id for item in findings} == {"TF-PLAN-001", "TF-PLAN-002"}
    assert run.name == "terraform_analyzer"


def test_kubeconform_maps_invalid_result(monkeypatch) -> None:
    resources = list(ManifestCollector([Path("samples/manifests/compliant")]).collect())[:1]

    def fake_run(command, **kwargs):
        filename = str(Path(command[-1]) / "0.yaml")
        return SimpleNamespace(
            stdout=json.dumps(
                [{"filename": filename, "status": "statusInvalid", "msg": "bad field"}]
            )
        )

    monkeypatch.setattr("infraguard.validators.kubeconform.run", fake_run)
    findings, run = KubeconformValidator().validate(resources)
    assert findings[0].policy_id == "SCHEMA-001"
    assert run.findings == 1


def test_kubeconform_accepts_valid_result(monkeypatch) -> None:
    resources = list(ManifestCollector([Path("samples/manifests/compliant")]).collect())[:1]
    monkeypatch.setattr(
        "infraguard.validators.kubeconform.run",
        lambda *args, **kwargs: SimpleNamespace(stdout="[]"),
    )
    findings, _ = KubeconformValidator().validate(resources)
    assert findings == []
