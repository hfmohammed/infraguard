from pathlib import Path

from prometheus_client import generate_latest

from infraguard.collectors.manifests import ManifestCollector
from infraguard.engine import run_scan
from infraguard.models import Severity
from infraguard.policies.catalog import PolicyCatalog
from infraguard.reporting.json_report import render_json, write_json
from infraguard.reporting.markdown_report import render_markdown, write_markdown
from infraguard.reporting.metrics import registry_for, write_metrics
from infraguard.reporting.table import print_table
from infraguard.validators.native import NativePolicyValidator


def sample_report():
    catalog = PolicyCatalog.load()
    collector = ManifestCollector([Path("samples/manifests/noncompliant")])
    return run_scan([collector], [NativePolicyValidator(catalog)], Severity.HIGH, catalog)


def test_engine_builds_sorted_failing_report() -> None:
    report = sample_report()
    assert report.summary.resources_scanned == 2
    assert report.summary.findings_total == 13
    assert report.summary.passed is False
    assert report.findings[0].severity is Severity.CRITICAL
    assert report.summary.policies_evaluated == 21


def test_fail_on_none_always_passes() -> None:
    catalog = PolicyCatalog.load()
    report = run_scan(
        [ManifestCollector([Path("samples/manifests/noncompliant")])],
        [NativePolicyValidator(catalog)],
        "NONE",
        catalog,
    )
    assert report.summary.passed is True


def test_json_round_trip_and_write(tmp_path: Path) -> None:
    report = sample_report()
    assert '"schema_version": "1.0"' in render_json(report)
    output = tmp_path / "nested" / "report.json"
    write_json(report, output)
    assert output.exists()
    import json

    import jsonschema

    schema = json.loads(Path("src/infraguard/reporting/schema/scan_report.schema.json").read_text())
    jsonschema.validate(json.loads(output.read_text()), schema)


def test_reports_are_stable_after_removing_execution_metadata() -> None:
    def normalized():
        payload = sample_report().model_dump(mode="json")
        for key in ("scan_id", "started_at", "finished_at", "duration_ms", "phase_durations_ms"):
            payload.pop(key)
        for execution in payload["validators"]:
            execution.pop("duration_ms")
        return payload

    assert normalized() == normalized()


def test_markdown_groups_findings_and_writes(tmp_path: Path) -> None:
    report = sample_report()
    rendered = render_markdown(report, Severity.HIGH)
    assert "# InfraGuard Scan Report" in rendered
    assert "## CRITICAL" in rendered
    assert "K8S-SEC-001" in rendered
    output = tmp_path / "report.md"
    write_markdown(report, output)
    assert output.read_text().endswith("\n")


def test_metrics_use_isolated_registry(tmp_path: Path) -> None:
    report = sample_report()
    text = generate_latest(registry_for(report)).decode()
    assert "infraguard_policy_violations_total" in text
    assert 'policy_id="K8S-SEC-001"' in text
    output = tmp_path / "metrics.prom"
    write_metrics(report, output)
    assert output.read_bytes().startswith(b"# HELP")


def test_table_prints_summary(capsys) -> None:
    print_table(sample_report())
    assert "FAILED" in capsys.readouterr().out
