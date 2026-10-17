"""YAML and Helm manifest collection."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import yaml

from infraguard.models import Resource, ResourceRef, SourceType
from infraguard.utils.redact import redact_manifest
from infraguard.utils.tools import run


class ManifestCollector:
    """Collect Kubernetes resources from YAML paths or rendered Helm output."""

    name = "manifests"
    source = SourceType.MANIFEST

    def __init__(
        self,
        paths: list[Path] | None = None,
        helm_chart: Path | None = None,
        values: list[Path] | None = None,
        release: str = "infraguard",
    ) -> None:
        self.paths = paths or []
        self.helm_chart = helm_chart
        self.values = values or []
        self.release = release

    def describe_target(self) -> str:
        """Describe source paths for reports."""
        if self.helm_chart:
            return f"helm:{self.helm_chart}"
        return "manifests:" + ",".join(str(path) for path in self.paths)

    def collect(self) -> Iterable[Resource]:
        """Yield every nonempty Kubernetes document safely."""
        for path in self._files():
            yield from self._parse(path.read_text(), str(path))
        if self.helm_chart:
            command = ["helm", "template", self.release, str(self.helm_chart)]
            for value in self.values:
                command.extend(["-f", str(value)])
            yield from self._parse(run(command).stdout, f"helm:{self.helm_chart}")

    def _files(self) -> list[Path]:
        files: set[Path] = set()
        for path in self.paths:
            if path.is_dir():
                files.update(path.rglob("*.yaml"))
                files.update(path.rglob("*.yml"))
            elif path.suffix.lower() in {".yaml", ".yml"}:
                files.add(path)
        return sorted(
            file for file in files if file.name not in {"kustomization.yaml", "kustomization.yml"}
        )

    def _parse(self, content: str, source: str) -> Iterable[Resource]:
        for document in yaml.safe_load_all(content):
            if not isinstance(document, dict) or not document:
                continue
            metadata = document.get("metadata") or {}
            kind = str(document.get("kind", "Unknown"))
            namespace = metadata.get("namespace")
            if kind != "Namespace" and not namespace:
                namespace = "default"
            yield Resource(
                ref=ResourceRef(
                    source=self.source,
                    kind=kind,
                    name=str(metadata.get("name", "unnamed")),
                    namespace=namespace,
                    api_version=document.get("apiVersion"),
                    file=source,
                ),
                labels=metadata.get("labels") or {},
                annotations=metadata.get("annotations") or {},
                raw=redact_manifest(document),
                collected_at=datetime.now(UTC),
            )
