"""Rich terminal table output."""

from rich.console import Console
from rich.table import Table

from infraguard.models import ScanReport


def print_table(report: ScanReport, console: Console | None = None) -> None:
    """Print findings and summary to a terminal."""
    console = console or Console()
    table = Table(title=f"InfraGuard {report.scan_id[:8]}")
    table.add_column("Severity")
    table.add_column("Policy")
    table.add_column("Resource")
    table.add_column("Message")
    for finding in report.findings:
        style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}[
            finding.severity.value
        ]
        table.add_row(
            f"[{style}]{finding.severity.value}[/{style}]",
            finding.policy_id,
            finding.resource.key(),
            finding.message,
        )
    console.print(table)
    status = "PASSED" if report.summary.passed else "FAILED"
    console.print(
        f"{status}: {report.summary.resources_scanned} resources, "
        f"{report.summary.findings_total} findings"
    )
