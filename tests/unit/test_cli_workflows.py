import json
from pathlib import Path

from typer.testing import CliRunner

from infraguard.cli import app
from infraguard.remediation.models import PipelineResult, StepResult

runner = CliRunner()


def test_policies_json_lists_all_entries() -> None:
    result = runner.invoke(app, ["policies", "list", "--format", "json"])
    assert result.exit_code == 0
    assert len(json.loads(result.stdout)) == 21


def test_policies_markdown_has_table() -> None:
    result = runner.invoke(app, ["policies", "list", "--format", "md"])
    assert result.exit_code == 0
    assert "| K8S-SEC-001 | CRITICAL |" in result.stdout


def test_validate_compliant_passes(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "validate",
            "--offline",
            "samples/manifests/compliant",
            "--fail-on",
            "LOW",
            "--format",
            "json",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_validate_noncompliant_fails_gate() -> None:
    result = runner.invoke(
        app,
        ["validate", "--offline", "samples/manifests/noncompliant", "--fail-on", "HIGH"],
    )
    assert result.exit_code == 1
    assert "FAILED" in result.stdout


def test_validate_none_passes_noncompliant() -> None:
    result = runner.invoke(
        app,
        ["validate", "--offline", "samples/manifests/noncompliant", "--fail-on", "NONE"],
    )
    assert result.exit_code == 0
    assert "PASSED" in result.stdout


def test_validate_requires_a_target() -> None:
    result = runner.invoke(app, ["validate"])
    assert result.exit_code == 2


def test_scan_plan_only_and_rerender(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--offline",
            "--no-cluster",
            "--plan-json",
            "samples/terraform/plan-fixtures/destroy.plan.fixture.json",
            "--fail-on",
            "NONE",
            "--format",
            "json",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    report_path = next(tmp_path.glob("*.json"))
    rendered = runner.invoke(app, ["report", str(report_path), "--format", "markdown"])
    assert rendered.exit_code == 0
    assert "InfraGuard Scan Report" in rendered.stdout


def test_scan_requires_at_least_one_target() -> None:
    result = runner.invoke(app, ["scan", "--no-cluster"])
    assert result.exit_code == 2


def test_invalid_severity_is_a_usage_error():
    result = runner.invoke(
        app, ["validate", "--offline", "samples/manifests/compliant", "--fail-on", "TYPO"]
    )
    assert result.exit_code == 2
    assert "--fail-on" in result.output


def test_schema_only_cannot_be_combined_with_offline():
    result = runner.invoke(
        app, ["validate", "--offline", "--schema-only", "samples/manifests/compliant"]
    )
    assert result.exit_code == 2


def test_report_table_and_metrics_formats(tmp_path):
    scan = runner.invoke(
        app,
        [
            "validate",
            "--offline",
            "samples/manifests/compliant",
            "--format",
            "json",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert scan.exit_code == 0
    report = str(next(tmp_path.glob("*.json")))
    table = runner.invoke(app, ["report", report, "--format", "table"])
    assert table.exit_code == 0
    assert "PASSED" in table.stdout
    metrics = runner.invoke(app, ["report", report, "--format", "prometheus"])
    assert metrics.exit_code == 0
    assert "infraguard_last_scan_passed 1.0" in metrics.stdout


def test_remediation_apply_refuses_noninteractive(tmp_path: Path, monkeypatch) -> None:
    proposal = {
        "proposal_id": "demo",
        "finding_fingerprint": "abc",
        "policy_id": "K8S-SEC-001",
        "target": {
            "source": "kubernetes_live",
            "kind": "Deployment",
            "name": "api",
            "namespace": "prod",
        },
        "proposed_manifest": {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "api", "namespace": "prod"},
            "spec": {},
        },
        "rationale": "disable privileged mode",
        "proposer": "external_ai",
        "created_at": "2026-10-20T12:00:00Z",
    }
    path = tmp_path / "proposal.yaml"
    import yaml

    path.write_text(yaml.safe_dump(proposal))
    checked_result = PipelineResult(
        proposal_id="demo",
        steps=[StepResult(step="schema", result="pass", duration_ms=0)],
        applied=False,
    )
    monkeypatch.setattr("infraguard.cli.check_proposal", lambda *args, **kwargs: checked_result)

    def reject_noninteractive(*args, **kwargs):
        raise RuntimeError("approval requires an interactive terminal")

    monkeypatch.setattr("infraguard.cli.apply_proposal", reject_noninteractive)
    checked = runner.invoke(app, ["remediate", "check", str(path)])
    applied = runner.invoke(app, ["remediate", "apply", str(path)])
    assert checked.exit_code == 0
    assert applied.exit_code == 4
    assert "interactive terminal" in applied.stdout
