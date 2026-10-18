"""InfraGuard command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal, cast

import typer
import yaml
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
from infraguard.remediation.approval import request_approval
from infraguard.remediation.models import RemediationProposal
from infraguard.remediation.pipeline import validate_proposal
from infraguard.reporting.json_report import render_json, write_json
from infraguard.reporting.markdown_report import render_markdown, write_markdown
from infraguard.reporting.metrics import write_metrics
from infraguard.reporting.table import print_table
from infraguard.validators.native import NativePolicyValidator

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


def version_callback(value: bool) -> None:
    """Print package version and stop."""
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def root(
    version: bool = typer.Option(False, "--version", callback=version_callback, is_eager=True),
) -> None:
    """Run InfraGuard."""


def _severity(value: str) -> Severity | str:
    return "NONE" if value == "NONE" else Severity(value)


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
    paths: Annotated[list[Path] | None, typer.Argument()] = None,
    helm_chart: Annotated[Path | None, typer.Option()] = None,
    values: Annotated[list[Path] | None, typer.Option()] = None,
    plan_json: Annotated[Path | None, typer.Option()] = None,
    fail_on: Annotated[str, typer.Option()] = "HIGH",
    format: Annotated[list[str] | None, typer.Option("--format")] = None,
    output_dir: Annotated[Path, typer.Option()] = Path("reports"),
    metrics_file: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Validate manifests, a Helm chart, and/or an existing Terraform plan."""
    collectors: list[Collector] = []
    if paths or helm_chart:
        collectors.append(ManifestCollector(paths or [], helm_chart, values or []))
    if plan_json:
        collectors.append(TerraformPlanCollector(plan_json=plan_json))
    if not collectors:
        raise typer.BadParameter("provide a YAML path, --helm-chart, or --plan-json")
    catalog = PolicyCatalog.load()
    try:
        report = run_scan(collectors, [NativePolicyValidator(catalog)], _severity(fail_on), catalog)  # type: ignore[arg-type]
        _emit(report, format or ["table"], output_dir, metrics_file)
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
    terraform_dir: Annotated[Path | None, typer.Option()] = None,
    plan_json: Annotated[Path | None, typer.Option()] = None,
    fail_on: Annotated[str, typer.Option()] = "HIGH",
    format: Annotated[list[str] | None, typer.Option("--format")] = None,
    output_dir: Annotated[Path, typer.Option()] = Path("reports"),
    metrics_file: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Scan a live cluster and/or Terraform plan."""
    collectors: list[Collector] = []
    if cluster:
        collectors.append(KubernetesLiveCollector(context, namespace))
    if terraform_dir or plan_json:
        collectors.append(TerraformPlanCollector(plan_json=plan_json, tf_dir=terraform_dir))
    if not collectors:
        raise typer.BadParameter("at least one scan target is required")
    catalog = PolicyCatalog.load()
    try:
        result = run_scan(collectors, [NativePolicyValidator(catalog)], _severity(fail_on), catalog)  # type: ignore[arg-type]
        _emit(result, format or ["table"], output_dir, metrics_file)
    except InfraGuardError as error:
        console.print(f"[red]ERROR:[/red] {error}")
        raise typer.Exit(3) from error
    if not result.summary.passed:
        raise typer.Exit(1)


@app.command()
def report(
    report_json: Path,
    format: Annotated[str, typer.Option()] = "markdown",
    output: Annotated[Path | None, typer.Option()] = None,
) -> None:
    """Re-render a saved JSON report."""
    model = ScanReport.model_validate_json(report_json.read_text())
    rendered = render_json(model) if format == "json" else render_markdown(model)
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
    else:
        for policy in policies:
            typer.echo(f"{policy.severity.value:8} {policy.id:16} {policy.title}")


@mcp_app.command("serve")
def mcp_serve(
    transport: Annotated[str, typer.Option()] = "stdio",
    context: Annotated[str | None, typer.Option()] = None,
    allowed_root: Annotated[Path, typer.Option()] = DEFAULT_ROOT,
) -> None:
    """Start the read-only MCP server."""
    configure_mcp(allowed_root=allowed_root, context=context)
    if transport not in {"stdio", "sse", "streamable-http"}:
        raise typer.BadParameter("transport must be stdio, sse, or streamable-http")
    serve_mcp(cast(Literal["stdio", "sse", "streamable-http"], transport))


def _load_proposal(path: Path) -> RemediationProposal:
    raw = yaml.safe_load(path.read_text())
    return RemediationProposal.model_validate(raw)


@remediate_app.command("check")
def remediate_check(proposal_yaml: Path) -> None:
    """Run the fail-closed proposal identity and scope checks."""
    step = validate_proposal(_load_proposal(proposal_yaml))
    typer.echo(step.model_dump_json(indent=2))
    if step.result == "fail":
        raise typer.Exit(1)


@remediate_app.command("apply")
def remediate_apply(proposal_yaml: Path) -> None:
    """Require interactive approval after validating a proposal."""
    proposal = _load_proposal(proposal_yaml)
    step = validate_proposal(proposal)
    if step.result == "fail":
        typer.echo(step.detail)
        raise typer.Exit(1)
    try:
        approved = request_approval(proposal.target.name)
    except RuntimeError as error:
        typer.echo(str(error))
        raise typer.Exit(4) from error
    if not approved:
        typer.echo("remediation rejected")
        raise typer.Exit(4)
    typer.echo(
        "approval recorded; use the Kubernetes client integration to perform server-side apply"
    )


def main() -> None:
    """Console-script entry point."""
    app()
