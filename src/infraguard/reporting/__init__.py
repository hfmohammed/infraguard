"""Report renderers."""

from infraguard.reporting.json_report import render_json
from infraguard.reporting.markdown_report import render_markdown

__all__ = ["render_json", "render_markdown"]
