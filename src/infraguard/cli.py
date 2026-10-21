"""InfraGuard command-line interface."""

from __future__ import annotations

import json
import logging
import os
from enum import StrEnum
from io import StringIO
from pathlib import Path
from threading import Event
from typing import Annotated, Literal, cast

import typer
import yaml
from prometheus_client import generate_latest
from rich.console import Console

from infraguard import __version__
from infraguard.collectors.base import Collector
from infraguard.collectors.kubernetes_live import KubernetesLiveCollector
from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.engine import run_scan
from infraguard.errors import InfraGuardError
from infraguard.mcp_server.server import configure as configure_mcp
from infraguard.mcp_server.server import serve as serve_mcp
from infraguard.models import ScanReport, Severity
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.models import RemediationProposal
from infraguard.remediation.pipeline import apply_proposal, check_proposal
from infraguard.remediation.proposer import propose
from infraguard.reporting.json_report import render_json, write_json
from infraguard.reporting.markdown_report import render_markdown, write_markdown
from infraguard.reporting.metrics import registry_for, serve_metrics, write_metrics
from infraguard.reporting.table import print_table
from infraguard.validators.registry import build_validators

app = typer.Typer(
    help="Validate Kubernetes and Terraform infrastructure safely.", no_args_is_help=True
)
policies_app = typer.Typer(help="Inspect the policy catalog.")
mcp_app = typer.Typer(help="Serve read-only infrastructure tools.")
remediate_app = typer.Typer(help="Validate guarded remediation proposals.")
app.add_typer(policies_app, name="policies")
app.add_typer(mcp_app, name="mcp")
app.add_typer(remediate_app, name="remediate")
console = Console()
DEFAULT_ROOT = Path.cwd()


class LogLevel(StrEnum):
    """Supported diagnostic logging levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


def version_callback(value: bool) -> None:
    """Print package version and stop."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", callback=version_callback, is_eager=True),
    no_color: Annotated[bool, typer.Option("--no-color")] = False,
    log_level: Annotated[LogLevel, typer.Option(case_sensitive=False)] = LogLevel.INFO,
) -> None:
    """Run InfraGuard."""
    logging.basicConfig(level=log_level.value.upper())
    if no_color:
        console.no_color = True
        os.environ["NO_COLOR"] = "1"


def _severity(value: str) -> Severity | Literal["NONE"]:
    try:
        return "NONE" if value == "NONE" else Severity(value)
    except ValueError as error:
        raise typer.BadParameter(
            "--fail-on must be CRITICAL, HIGH, MEDIUM, LOW, or NONE"
        ) from error


def _emit(
    report: ScanReport, formats: list[str], output_dir: Path, metrics_file: Path | None
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"scan-{report.scan_id[:8]}"
    for output_format in formats:
        if output_format == "table":
            print_table(report, console)
        elif output_format == "json":
            path = output_dir / f"{stem}.json"
            write_json(report, path)
            console.print(f"JSON report: {path}")
        elif output_format == "markdown":
            path = output_dir / f"{stem}.md"
            write_markdown(report, path)
            console.print(f"Markdown report: {path}")
        else:
            raise typer.BadParameter(f"unsupported format: {output_format}")
    if metrics_file:
        write_metrics(report, metrics_file)


@app.command()
def validate(
    paths: Annotated[list[Path] | None, typer.Argument(exists=True)] = None,
    helm_chart: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    values: Annotated[list[Path] | None, typer.Option(exists=True, dir_okay=False)] = None,
    plan_json: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    terraform_dir: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    policy_dir: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    schema_only: Annotated[bool, typer.Option()] = False,
    policy_only: Annotated[bool, typer.Option()] = False,
    fail_on: Annotated[str, typer.Option()] = "HIGH",
    format: Annotated[list[str] | None, typer.Option("--format")] = None,
    output_dir: Annotated[Path, typer.Option()] = Path("reports"),
    metrics_file: Annotated[Path | None, typer.Option()] = None,
    offline: Annotated[
        bool, typer.Option(help="Use native policies without external schema checks.")
    ] = False,
    serve_metrics_port: Annotated[
        int | None, typer.Option("--serve-metrics", min=1, max=65535)
    ] = None,
    metrics_host: Annotated[str, typer.Option()] = "127.0.0.1",
) -> None:
    """Validate manifests, a Helm chart, and/or an existing Terraform plan."""
    collectors: list[Collector] = []
    if paths or helm_chart:
        collectors.append(ManifestCollector(paths or [], helm_chart, values or []))
    if schema_only and (policy_only or offline):
        raise typer.BadParameter("--schema-only cannot be combined with --policy-only or --offline")
    if plan_json and terraform_dir:
        raise typer.BadParameter("provide --plan-json or --terraform-dir, not both")
    if plan_json or terraform_dir:
        collectors.append(TerraformPlanCollector(plan_json=plan_json, tf_dir=terraform_dir))
    if not collectors:
        raise typer.BadParameter("provide a YAML path, --helm-chart, or --plan-json")
    catalog = PolicyCatalog.load(policy_dir / "metadata.yaml" if policy_dir else None)
    validators = build_validators(
        catalog, offline=offline, policy_root=policy_dir, skip_schema=policy_only
    )
    if schema_only:
        validators = [validator for validator in validators if validator.name == "kubeconform"]
    try:
        report = run_scan(collectors, validators, _severity(fail_on), catalog)
        _emit(report, format or ["table"], output_dir, metrics_file)
        _serve(report, serve_metrics_port, metrics_host)
    except InfraGuardError as error:
        console.print(f"[red]ERROR:[/red] {error}")
        raise typer.Exit(3) from error
    if not report.summary.passed:
        raise typer.Exit(1)


@app.command()
def scan(
    cluster: Annotated[bool, typer.Option("--cluster/--no-cluster")] = True,
    context: Annotated[str | None, typer.Option()] = None,
    namespace: Annotated[list[str] | None, typer.Option("--namespace", "-n")] = None,
    terraform_dir: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    plan_json: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    policy_dir: Annotated[Path | None, typer.Option(exists=True, file_okay=False)] = None,
    skip_schema: Annotated[bool, typer.Option()] = False,
    fail_on: Annotated[str, typer.Option()] = "HIGH",
    format: Annotated[list[str] | None, typer.Option("--format")] = None,
    output_dir: Annotated[Path, typer.Option()] = Path("reports"),
    metrics_file: Annotated[Path | None, typer.Option()] = None,
    offline: Annotated[
        bool, typer.Option(help="Use native policies without external schema checks.")
    ] = False,
    serve_metrics_port: Annotated[
        int | None, typer.Option("--serve-metrics", min=1, max=65535)
    ] = None,
    metrics_host: Annotated[str, typer.Option()] = "127.0.0.1",
) -> None:
    """Scan a live cluster and/or Terraform plan."""
    collectors: list[Collector] = []
    if plan_json and terraform_dir:
        raise typer.BadParameter("provide --plan-json or --terraform-dir, not both")
    if cluster:
        collectors.append(KubernetesLiveCollector(context, namespace))
    if terraform_dir or plan_json:
        collectors.append(TerraformPlanCollector(plan_json=plan_json, tf_dir=terraform_dir))
    if not collectors:
        raise typer.BadParameter("at least one scan target is required")
    catalog = PolicyCatalog.load(policy_dir / "metadata.yaml" if policy_dir else None)
    try:
        result = run_scan(
            collectors,
            build_validators(
                catalog, offline=offline, policy_root=policy_dir, skip_schema=skip_schema
            ),
            _severity(fail_on),
            catalog,
        )
        _emit(result, format or ["table"], output_dir, metrics_file)
        _serve(result, serve_metrics_port, metrics_host)
    except InfraGuardError as error:
        console.print(f"[red]ERROR:[/red] {error}")
        raise typer.Exit(3) from error
    if not result.summary.passed:
        raise typer.Exit(1)


def _serve(report: ScanReport, port: int | None, host: str) -> None:
    if port is None:
        return
    server, thread = serve_metrics(report, port=port, host=host)
    typer.echo(f"Metrics: http://{host}:{server.server_port}/metrics (Ctrl-C to stop)")
    try:
        Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@app.command()
def report(
    report_json: Path,
    format: Annotated[str, typer.Option()] = "markdown",
    output: Annotated[Path | None, typer.Option()] = None,
    min_severity: Annotated[Severity, typer.Option()] = Severity.LOW,
) -> None:
    """Re-render a saved JSON report."""
    model = ScanReport.model_validate_json(report_json.read_text())
    filtered = model.model_copy(
        update={"findings": [f for f in model.findings if f.severity.rank >= min_severity.rank]}
    )
    if format == "json":
        rendered = render_json(filtered)
    elif format == "markdown":
        rendered = render_markdown(model, min_severity)
    elif format == "prometheus":
        rendered = generate_latest(registry_for(model)).decode()
    elif format == "table":
        buffer = StringIO()
        print_table(filtered, Console(file=buffer, width=120))
        rendered = buffer.getvalue()
    else:
        raise typer.BadParameter("--format must be markdown, table, json, or prometheus")
    if output:
        output.write_text(rendered)
    else:
        typer.echo(rendered)


@policies_app.command("list")
def list_policies(format: Annotated[str, typer.Option()] = "table") -> None:
    """List policy metadata."""
    policies = PolicyCatalog.load().all()
    if format == "json":
        typer.echo(json.dumps([policy.model_dump(mode="json") for policy in policies], indent=2))
    elif format == "md":
        typer.echo("# Policy catalog\n\n| ID | Severity | Title | Engine |\n|---|---|---|---|")
        for policy in policies:
            typer.echo(
                f"| {policy.id} | {policy.severity.value} | {policy.title} | {policy.engine} |"
            )
        typer.echo(
            "\n## Evaluation notes\n\n"
            "Normal scans combine kubeconform, Conftest/Rego, and native inventory/action checks. "
            "`SCHEMA-001` is a schema diagnostic, separate from the 21 catalog controls.\n\n"
            "S3 companion resources join by known bucket names or by Terraform configuration "
            "references when planned IDs are unknown. The collector retains only those references "
            "and removes configuration constants and variables from the redacted plan. "
            "Deleted companion resources do not satisfy a protective control.\n\n"
            "NetworkPolicy coverage means a policy exists in the namespace; it does not prove "
            "that its selectors and traffic rules protect every workload.\n"
        )
    else:
        for policy in policies:
            typer.echo(f"{policy.severity.value:8} {policy.id:16} {policy.title}")


@mcp_app.command("serve")
def mcp_serve(
    transport: Annotated[str, typer.Option()] = "stdio",
    context: Annotated[str | None, typer.Option()] = None,
    allowed_root: Annotated[Path, typer.Option()] = DEFAULT_ROOT,
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8765,
) -> None:
    """Start the read-only MCP server."""
    configure_mcp(allowed_root=allowed_root, context=context)
    from infraguard.mcp_server.server import mcp

    mcp.settings.port = port
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise typer.BadParameter("transport must be stdio, sse, or streamable-http")
    serve_mcp(cast(Literal["stdio", "sse", "streamable-http"], transport))


def _load_proposal(path: Path) -> RemediationProposal:
    raw = yaml.safe_load(path.read_text())
    return RemediationProposal.model_validate(raw)


@remediate_app.command("propose")
def remediate_propose(
    report_json: Annotated[Path, typer.Option("--report")],
    finding_fingerprint: Annotated[str, typer.Option("--finding")],
    output: Annotated[Path, typer.Option("--out")] = Path("proposal.yaml"),
    context: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Build a deterministic proposal from a live-resource finding."""
    report_model = ScanReport.model_validate_json(report_json.read_text())
    finding = next(
        (item for item in report_model.findings if item.fingerprint == finding_fingerprint),
        None,
    )
    if finding is None:
        raise typer.BadParameter(f"finding not found: {finding_fingerprint}")
    resources = KubernetesLiveCollector(
        context=context,
        namespaces=[finding.resource.namespace] if finding.resource.namespace else None,
    ).collect()
    resource = next(
        (
            item
            for item in resources
            if item.ref.kind == finding.resource.kind
            and item.ref.name == finding.resource.name
            and item.ref.namespace == finding.resource.namespace
        ),
        None,
    )
    if resource is None:
        raise typer.BadParameter(f"live resource not found: {finding.resource.key()}")
    proposal = propose(finding, resource)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(proposal.model_dump(mode="json"), sort_keys=False))
    typer.echo(f"Proposal written: {output}")


@remediate_app.command("check")
def remediate_check(
    proposal_yaml: Path,
    context: Annotated[str | None, typer.Option()] = None,
    take_ownership: Annotated[
        bool, typer.Option(help="Simulate transfer of conflicting field ownership.")
    ] = False,
) -> None:
    """Run schema, policy, and server-side dry-run checks without applying."""
    result = check_proposal(
        _load_proposal(proposal_yaml), context=context, take_ownership=take_ownership
    )
    typer.echo(result.model_dump_json(indent=2))
    if any(step.result == "fail" for step in result.steps):
        raise typer.Exit(1)


@remediate_app.command("apply")
def remediate_apply(
    proposal_yaml: Path,
    context: Annotated[str | None, typer.Option()] = None,
    take_ownership: Annotated[
        bool, typer.Option(help="Transfer conflicting fields only after approval.")
    ] = False,
) -> None:
    """Run every gate and apply only after interactive human approval."""
    proposal = _load_proposal(proposal_yaml)
    try:
        result = apply_proposal(proposal, context=context, take_ownership=take_ownership)
    except RuntimeError as error:
        typer.echo(str(error))
        raise typer.Exit(4) from error
    typer.echo(result.model_dump_json(indent=2))
    if any(step.result == "fail" for step in result.steps):
        raise typer.Exit(1)
    if not result.applied:
        raise typer.Exit(4)


def main() -> None:
    """Console-script entry point."""
    app()
