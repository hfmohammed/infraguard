#!/usr/bin/env python3
"""Generate README visuals from real InfraGuard fixtures and runtime metadata."""

from pathlib import Path

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.terminal_theme import MONOKAI

from infraguard.collectors.manifests import ManifestCollector
from infraguard.collectors.terraform_plan import TerraformPlanCollector
from infraguard.engine import run_scan
from infraguard.mcp_server.server import mcp
from infraguard.policies.catalog import PolicyCatalog
from infraguard.reporting.markdown_report import render_markdown
from infraguard.reporting.table import print_table
from infraguard.validators.native import NativePolicyValidator

OUTPUT = Path("docs/images")


def console(width: int = 120) -> Console:
    """Return a recording console with a stable terminal theme."""
    return Console(record=True, width=width, color_system="truecolor", force_terminal=True)


def export(recording: Console, name: str, title: str) -> None:
    """Export a recorded console as a GitHub-renderable SVG."""
    OUTPUT.mkdir(parents=True, exist_ok=True)
    svg = recording.export_svg(title=title, theme=MONOKAI, clear=False)
    (OUTPUT / name).write_text(svg, encoding="utf-8")


def build_report():
    """Run the same deterministic offline scan used by the README quick demo."""
    catalog = PolicyCatalog.load()
    collectors = [
        ManifestCollector([Path("samples/manifests/noncompliant")]),
        TerraformPlanCollector(
            plan_json=Path("samples/terraform/plan-fixtures/noncompliant.plan.fixture.json")
        ),
    ]
    return run_scan(
        collectors,
        [NativePolicyValidator(catalog)],
        fail_on="NONE",
        catalog=catalog,
    )


def scan_visual(report) -> None:
    recording = console(132)
    recording.print(
        Panel.fit(
            "[bold cyan]InfraGuard v0.1.0[/]  [dim]offline policy scan[/]\n"
            "[green]✓[/] Kubernetes manifests  [green]✓[/] Terraform plan  "
            "[green]✓[/] 21 policies",
            border_style="cyan",
        )
    )
    print_table(report, recording)
    export(recording, "scan-table.svg", "InfraGuard policy scan")


def report_visual(report) -> None:
    markdown = render_markdown(report)
    excerpt = markdown.split("## Validator runs", 1)[0]
    recording = console(112)
    recording.print(Markdown(excerpt))
    export(recording, "markdown-report.svg", "InfraGuard Markdown report")


def metrics_visual(report) -> None:
    recording = console(108)
    recording.print("[bold cyan]InfraGuard · latest scan[/]\n")
    cards = Table.grid(expand=True)
    cards.add_column(ratio=1)
    cards.add_column(ratio=1)
    cards.add_column(ratio=1)
    cards.add_row(
        Panel(
            f"[bold white]{report.summary.resources_scanned}[/]\n[dim]Resources scanned[/]",
            border_style="cyan",
        ),
        Panel(
            f"[bold white]{report.summary.findings_total}[/]\n[dim]Policy findings[/]",
            border_style="yellow",
        ),
        Panel("[bold green]PASSED[/]\n[dim]Demo threshold: NONE[/]", border_style="green"),
    )
    recording.print(cards)
    severity = Table(title="Findings by severity", expand=True)
    severity.add_column("CRITICAL", justify="center", style="bold red")
    severity.add_column("HIGH", justify="center", style="red")
    severity.add_column("MEDIUM", justify="center", style="yellow")
    severity.add_column("LOW", justify="center", style="cyan")
    counts = report.summary.by_severity
    severity.add_row(str(counts.CRITICAL), str(counts.HIGH), str(counts.MEDIUM), str(counts.LOW))
    recording.print(severity)
    export(recording, "metrics-dashboard.svg", "InfraGuard metrics summary")


def mcp_visual() -> None:
    tools = sorted(mcp._tool_manager._tools)
    descriptions = {
        "list_cluster_resources": "Inventory refs and labels",
        "get_resource": "Return one redacted manifest",
        "get_policy_findings": "Filter saved or live findings",
        "analyze_terraform_plan": "Analyze existing plan JSON only",
        "validate_manifest": "Validate supplied YAML",
        "validate_patch": "Run checks; never apply",
    }
    recording = console(104)
    table = Table(title="Read-only MCP surface", expand=True)
    table.add_column("Tool", style="bold cyan")
    table.add_column("Capability")
    table.add_column("Mutation", justify="center")
    for name in tools:
        table.add_row(name, descriptions[name], "[green]blocked[/]")
    recording.print(table)
    recording.print(
        Panel(
            "[green]✓[/] path confinement   [green]✓[/] secret redaction   "
            "[green]✓[/] input limits   [green]✓[/] dry-run-only patch validation",
            border_style="green",
        )
    )
    export(recording, "mcp-tools.svg", "InfraGuard MCP tools")


def guardrail_visual() -> None:
    recording = console(108)
    recording.print(
        Panel.fit(
            "[bold]InfraGuard remediation approval[/]\n\n"
            "Proposal   [cyan]6c13e30a[/]  (rule_based)\n"
            "Finding    [bold red]K8S-SEC-001 · Privileged container[/]\n"
            "Target     ig-noncompliant/Deployment/vulnerable-app\n\n"
            "Checks     schema [green]✓[/]   policy [green]✓[/]   "
            "dry-run [green]✓[/]   approval [yellow]waiting[/]\n\n"
            "[red]- privileged: true[/]\n"
            "[green]+ privileged: false[/]\n\n"
            'Type the resource name [bold]"vulnerable-app"[/] to approve.',
            border_style="yellow",
            title="Human approval boundary",
        )
    )
    export(recording, "approval-prompt.svg", "InfraGuard approval prompt")


def main() -> None:
    """Regenerate every employer-facing README visual."""
    report = build_report()
    scan_visual(report)
    report_visual(report)
    metrics_visual(report)
    mcp_visual()
    guardrail_visual()
    print(f"generated 5 visuals in {OUTPUT}")


if __name__ == "__main__":
    main()
