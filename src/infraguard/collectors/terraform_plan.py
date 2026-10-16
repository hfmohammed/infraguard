"""Read-only Terraform plan JSON collection."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from infraguard.models import Resource, ResourceRef, SourceType, TerraformChange
from infraguard.utils.redact import redact_sensitive
from infraguard.utils.tools import run


class TerraformPlanCollector:
    """Normalize resources from existing or ephemeral Terraform plans."""

    name = "terraform_plan"
    source = SourceType.TERRAFORM_PLAN

    def __init__(self, plan_json: Path | None = None, tf_dir: Path | None = None) -> None:
        if (plan_json is None) == (tf_dir is None):
            raise ValueError("provide exactly one of plan_json or tf_dir")
        self.plan_json = plan_json
        self.tf_dir = tf_dir
        self._plan: dict[str, Any] | None = None

    def describe_target(self) -> str:
        """Return the stable report target."""
        return f"terraform:{self.plan_json or self.tf_dir}"

    def plan(self) -> dict[str, Any]:
        """Return the redacted plan, loading or generating it once."""
        if self._plan is None:
            self._plan = self._load_plan()
        return self._plan

    def changes(self) -> list[TerraformChange]:
        """Return typed changes from the plan."""
        return [
            TerraformChange(
                address=str(change["address"]),
                type=str(change["type"]),
                name=str(change["name"]),
                actions=change.get("change", {}).get("actions", []),
                before=change.get("change", {}).get("before"),
                after=change.get("change", {}).get("after"),
            )
            for change in self.plan().get("resource_changes", [])
        ]

    def collect(self) -> Iterable[Resource]:
        """Yield one normalized resource per Terraform change."""
        now = datetime.now(UTC)
        for raw in self.plan().get("resource_changes", []):
            change = raw.get("change", {})
            cleaned = dict(raw)
            cleaned["change"] = dict(change)
            cleaned["change"]["before"] = redact_sensitive(change.get("before"), change.get("before_sensitive", False))
            cleaned["change"]["after"] = redact_sensitive(change.get("after"), change.get("after_sensitive", False))
            yield Resource(
                ref=ResourceRef(
                    source=self.source,
                    kind=str(raw["type"]),
                    name=str(raw["name"]),
                    address=str(raw["address"]),
                ),
                raw=cleaned,
                collected_at=now,
            )

    def _load_plan(self) -> dict[str, Any]:
        if self.plan_json:
            data = json.loads(self.plan_json.read_text())
            if not isinstance(data, dict):
                raise ValueError("Terraform plan JSON must be an object")
            return data
        assert self.tf_dir is not None
        with tempfile.TemporaryDirectory(prefix="infraguard-tf-") as temporary:
            root = Path(temporary)
            work = root / "module"
            shutil.copytree(self.tf_dir, work)
            environment = os.environ.copy()
            environment.update(
                AWS_ACCESS_KEY_ID="mock",
                AWS_SECRET_ACCESS_KEY="mock",
                AWS_REGION="us-east-1",
                TF_DATA_DIR=str(root / "data"),
                TF_PLUGIN_CACHE_DIR=str(Path.cwd() / ".cache" / "terraform-plugins"),
            )
            # The shared runner deliberately owns command construction; environment is
            # set only for this process by temporarily updating os.environ.
            previous = os.environ.copy()
            try:
                os.environ.update(environment)
                run(["terraform", "init", "-backend=false", "-input=false"], cwd=work, timeout=300)
                plan_path = root / "tfplan"
                run(["terraform", "plan", "-input=false", "-lock=false", "-refresh=false", f"-out={plan_path}"], cwd=work, timeout=300)
                output = run(["terraform", "show", "-json", str(plan_path)], cwd=work).stdout
            finally:
                os.environ.clear()
                os.environ.update(previous)
            return json.loads(output)

