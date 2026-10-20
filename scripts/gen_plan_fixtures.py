#!/usr/bin/env python3
"""Print sanitized fixture JSON from a temporary, refresh-free Terraform plan."""

import argparse
import json
from pathlib import Path

from infraguard.collectors.terraform_plan import TerraformPlanCollector


def main() -> None:
    """Generate only a plan; exclude configuration constants and provider secrets."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    options = parser.parse_args()
    plan = TerraformPlanCollector(tf_dir=options.module).plan()
    sanitized = {
        key: plan[key]
        for key in ("format_version", "terraform_version", "resource_changes", "output_changes")
        if key in plan
    }
    print(json.dumps(sanitized, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
