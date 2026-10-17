"""kubeconform schema validator wrapper."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from time import perf_counter

import yaml

from infraguard.models import Category, Finding, Resource, Severity, ValidatorRun
from infraguard.utils.tools import run


class KubeconformValidator:
    """Validate Kubernetes resources against strict upstream schemas."""

    name = "kubeconform"

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]:
        """Run kubeconform and map invalid documents to SCHEMA-001."""
        started = perf_counter()
        findings: list[Finding] = []
        with tempfile.TemporaryDirectory(prefix="infraguard-schema-") as temporary:
            root = Path(temporary)
            lookup: dict[str, Resource] = {}
            for index, resource in enumerate(resources):
                path = root / f"{index}.yaml"
                path.write_text(yaml.safe_dump(resource.raw))
                lookup[str(path)] = resource
            result = run(
                [
                    "kubeconform",
                    "-strict",
                    "-summary",
                    "-output",
                    "json",
                    "-kubernetes-version",
                    "1.30.0",
                    "-skip",
                    "CustomResourceDefinition",
                    str(root),
                ],
                ok_codes=(0, 1),
            )
            for item in json.loads(result.stdout or "[]"):
                if item.get("status") not in {"statusInvalid", "statusError"}:
                    continue
                matched = lookup.get(item.get("filename"))
                if matched:
                    findings.append(
                        Finding.create(
                            policy_id="SCHEMA-001",
                            title="Schema validation failed",
                            severity=Severity.HIGH,
                            category=Category.SCHEMA,
                            resource=matched.ref,
                            message=item.get("msg", "invalid Kubernetes manifest"),
                            remediation="Fix the manifest to match its Kubernetes API schema",
                            validator="kubeconform",
                        )
                    )
        return findings, ValidatorRun(
            name=self.name,
            duration_ms=(perf_counter() - started) * 1000,
            resources_checked=len(resources),
            findings=len(findings),
        )
