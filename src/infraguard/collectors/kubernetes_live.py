"""Read-only Kubernetes API inventory collection."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from kubernetes.config.config_exception import ConfigException

from infraguard.errors import ClusterUnreachableError
from infraguard.models import Resource, ResourceRef, SourceType
from infraguard.utils.redact import redact_manifest


class KubernetesLiveCollector:
    """Collect supported Kubernetes resources using list-only API calls."""

    name = "kubernetes_live"
    source = SourceType.KUBERNETES_LIVE
    excluded_default = ("kube-system", "kube-public", "kube-node-lease", "local-path-storage")

    def __init__(
        self,
        context: str | None = None,
        namespaces: list[str] | None = None,
        exclude_namespaces: tuple[str, ...] = excluded_default,
    ) -> None:
        self.context = context
        self.namespaces = namespaces
        self.exclude_namespaces = exclude_namespaces

    def describe_target(self) -> str:
        """Return Kubernetes context target label."""
        return f"cluster:{self.context or 'current'}"

    def collect(self) -> Iterable[Resource]:
        """List supported resources, skipping system namespaces and owned pods."""
        try:
            try:
                config.load_kube_config(context=self.context)
            except ConfigException:
                config.load_incluster_config()
            core, apps, batch, networking = (
                client.CoreV1Api(),
                client.AppsV1Api(),
                client.BatchV1Api(),
                client.NetworkingV1Api(),
            )
            calls = [
                (core.list_namespace, "Namespace", "v1", False),
                (core.list_pod_for_all_namespaces, "Pod", "v1", True),
                (core.list_service_for_all_namespaces, "Service", "v1", True),
                (apps.list_deployment_for_all_namespaces, "Deployment", "apps/v1", True),
                (apps.list_stateful_set_for_all_namespaces, "StatefulSet", "apps/v1", True),
                (apps.list_daemon_set_for_all_namespaces, "DaemonSet", "apps/v1", True),
                (batch.list_job_for_all_namespaces, "Job", "batch/v1", True),
                (batch.list_cron_job_for_all_namespaces, "CronJob", "batch/v1", True),
                (
                    networking.list_ingress_for_all_namespaces,
                    "Ingress",
                    "networking.k8s.io/v1",
                    True,
                ),
                (
                    networking.list_network_policy_for_all_namespaces,
                    "NetworkPolicy",
                    "networking.k8s.io/v1",
                    True,
                ),
            ]
            for call, kind, api_version, namespaced in calls:
                yield from self._paginate(call, kind, api_version, namespaced)
        except (ApiException, ConfigException, OSError) as error:
            raise ClusterUnreachableError(f"Kubernetes cluster is unreachable: {error}") from error

    def _paginate(
        self, call: Any, kind: str, api_version: str, namespaced: bool
    ) -> Iterable[Resource]:
        token: str | None = None
        api_client = client.ApiClient()
        while True:
            response = call(limit=500, _continue=token)
            for item in response.items:
                raw = api_client.sanitize_for_serialization(item)
                namespace = raw.get("metadata", {}).get("namespace") if namespaced else None
                if namespace in self.exclude_namespaces or (
                    self.namespaces and namespace not in self.namespaces
                ):
                    continue
                owners = raw.get("metadata", {}).get("ownerReferences", [])
                if kind == "Pod" and any(
                    owner.get("kind") in {"ReplicaSet", "StatefulSet", "DaemonSet", "Job"}
                    for owner in owners
                ):
                    continue
                raw.update(apiVersion=api_version, kind=kind)
                metadata = raw.get("metadata", {})
                yield Resource(
                    ref=ResourceRef(
                        source=self.source,
                        kind=kind,
                        name=metadata["name"],
                        namespace=namespace,
                        api_version=api_version,
                    ),
                    labels=metadata.get("labels") or {},
                    annotations=metadata.get("annotations") or {},
                    raw=redact_manifest(raw),
                    collected_at=datetime.now(UTC),
                )
            token = getattr(getattr(response, "metadata", None), "_continue", None)
            if not token:
                break
