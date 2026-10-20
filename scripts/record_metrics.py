#!/usr/bin/env python3
"""Print reproducible local metrics without inventing unavailable values."""

import subprocess
from pathlib import Path

from infraguard.policies.catalog import PolicyCatalog

catalog = PolicyCatalog.load()
collected = subprocess.run(
    ["pytest", "--collect-only", "-q"], capture_output=True, text=True, check=True
)
count_line = collected.stdout.strip().splitlines()[-1]
print(f"Policies: {len(catalog)}")
print(f"Tests: {count_line}")
print(
    f"Commit: {subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], text=True).strip()}"
)
print(f"Metrics file: {Path('docs/METRICS.md').resolve()}")
