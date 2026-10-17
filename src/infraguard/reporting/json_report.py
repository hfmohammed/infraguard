"""JSON report serialization."""

from pathlib import Path

from infraguard.models import ScanReport


def render_json(report: ScanReport) -> str:
    """Serialize a scan report as pretty JSON."""
    return report.model_dump_json(indent=2)


def write_json(report: ScanReport, output: Path) -> None:
    """Write a JSON report, creating its parent directory."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_json(report) + "\n")
