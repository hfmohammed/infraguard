from pathlib import Path

import pytest

from infraguard.mcp_server import server
from infraguard.remediation.models import PipelineResult, StepResult
from infraguard.validators.native import NativePolicyValidator


@pytest.fixture(autouse=True)
def configured_root(monkeypatch, tmp_path) -> None:
    server.configure(allowed_root=Path.cwd())
    from infraguard.mcp_server.audit import configure_audit

    configure_audit(tmp_path)
    monkeypatch.setattr(
        server, "build_validators", lambda catalog: [NativePolicyValidator(catalog)]
    )


def test_analyze_plan_returns_change_summary() -> None:
    result = server.analyze_terraform_plan(
        "samples/terraform/plan-fixtures/destroy.plan.fixture.json"
    )
    assert result["changes"] == {"create": 0, "update": 0, "delete": 1, "replace": 1}
    assert {item["policy_id"] for item in result["findings"]} == {
        "TF-PLAN-001",
        "TF-PLAN-002",
    }


def test_validate_manifest_returns_findings() -> None:
    source = Path("samples/manifests/noncompliant/workloads.yaml").read_text()
    result = server.validate_manifest(source)
    assert result["passed"] is False
    assert len(result["findings"]) == 13


def test_validate_patch_never_applies(monkeypatch) -> None:
    def checked(proposal, **kwargs):
        return PipelineResult(
            proposal_id=proposal.proposal_id,
            steps=[StepResult(step="dry_run", result="pass", duration_ms=0)],
            diff="checked diff",
            applied=False,
        )

    monkeypatch.setattr(server, "check_proposal", checked)
    source = Path("samples/manifests/compliant/app.yaml").read_text().split("---", 1)[0]
    result = server.validate_patch("Deployment", "compliant-app", "ig-compliant", source)
    assert result["applied"] is False
    assert result["target_matches"] is True
    assert "human" in result["next_step"]


def test_manifest_limit_rejects_too_many_documents() -> None:
    with pytest.raises(ValueError, match="50 documents"):
        server.validate_manifest("\n---\n".join(["{}"] * 51))
