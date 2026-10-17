#!/usr/bin/env python3
"""Regenerate the committed ScanReport JSON Schema."""

import json
from pathlib import Path

from infraguard.models import ScanReport

output = Path("src/infraguard/reporting/schema/scan_report.schema.json")
output.write_text(json.dumps(ScanReport.model_json_schema(), indent=2) + "\n")
