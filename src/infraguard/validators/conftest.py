"""Conftest adapter with resource-aware decoding of structured Rego findings."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from time import perf_counter

from infraguard.errors import PolicyCatalogError, ToolError
from infraguard.models import Finding, Resource, SourceType, ValidatorRun
from infraguard.policies.catalog import PolicyCatalog, policy_directory
from infraguard.utils.tools import run


class ConftestValidator:
    """Evaluate Kubernetes documents and complete Terraform change inventories."""

    name = "conftest"

    def __init__(self, catalog: PolicyCatalog, policy_root: Path | None = None) -> None:
        self.catalog = catalog
        self.policy_root = policy_root or policy_directory()

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]:
        """Map Conftest failures back to their normalized resource identities."""
        started = perf_counter()
        findings: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="infraguard-policy-") as temporary:
            root = Path(temporary)
            for target in ("kubernetes", "terraform"):
                selected = [
                    r
                    for r in resources
                    if (r.ref.source == SourceType.TERRAFORM_PLAN) == (target == "terraform")
                ]
                if not selected:
                    continue
                lookup: dict[str, Resource] = {}
                files: list[str] = []
                if target == "terraform":
                    path = root / "plan.json"
                    path.write_text(json.dumps({"resource_changes": [r.raw for r in selected]}))
                    files.append(str(path))
                else:
                    for index, resource in enumerate(selected):
                        path = root / f"resource-{index}.json"
                        path.write_text(json.dumps(resource.raw))
                        lookup[str(path)] = resource
                        files.append(str(path))
                output = run(
                    [
                        "conftest",
                        "test",
                        "--policy",
                        str(self.policy_root / target),
                        "--all-namespaces",
                        "--output",
                        "json",
                        *files,
                    ],
                    ok_codes=(0, 1),
                )
                try:
                    results = json.loads(output.stdout)
                    for result in results:
                        for failure in result.get("failures", []):
                            message = json.loads(failure["msg"])
                            policy = self.catalog.get(message["id"])
                            matched = lookup.get(result["filename"])
                            if matched is None:
                                matched = next(
                                    (
                                        r
                                        for r in selected
                                        if r.ref.address == message.get("resource")
                                    ),
                                    None,
                                )
                            if matched is None:
                                raise ToolError("Conftest returned an unidentified resource")
                            findings.append(
                                Finding.create(
                                    policy_id=policy.id,
                                    title=policy.title,
                                    severity=policy.severity,
                                    category=policy.category,
                                    resource=matched.ref,
                                    message=message["msg"],
                                    remediation=policy.remediation,
                                    path=message.get("path"),
                                    validator="conftest",
                                )
                            )
                except PolicyCatalogError:
                    raise
                except (ValueError, KeyError, TypeError) as error:
                    raise ToolError(f"invalid Conftest JSON response: {error}") from error
        return findings, ValidatorRun(
            name=self.name,
            duration_ms=(perf_counter() - started) * 1000,
            resources_checked=len(resources),
            findings=len(findings),
        )
