"""Deterministic built-in evaluator used for fast offline scans."""

from __future__ import annotations

import json
from collections.abc import Iterable
from time import perf_counter
from typing import Any

from infraguard.models import Finding, Resource, SourceType, ValidatorRun
from infraguard.policies.catalog import PolicyCatalog

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"}
CONTROLLERS_WITH_PROBES = {"Deployment", "StatefulSet", "DaemonSet"}
DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "NET_RAW", "ALL"}
STATEFUL_TYPES = {
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_s3_bucket",
    "aws_dynamodb_table",
    "aws_ebs_volume",
}


def _pod_spec(raw: dict[str, Any]) -> dict[str, Any]:
    kind = raw.get("kind")
    if kind == "Pod":
        value = raw.get("spec") or {}
        return value if isinstance(value, dict) else {}
    if kind == "CronJob":
        value = (
            raw.get("spec", {})
            .get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
        return value if isinstance(value, dict) else {}
    value = raw.get("spec", {}).get("template", {}).get("spec", {})
    return value if isinstance(value, dict) else {}


def _containers(spec: dict[str, Any]) -> Iterable[tuple[int, dict[str, Any], str]]:
    for group in ("containers", "initContainers"):
        for index, container in enumerate(spec.get(group) or []):
            yield index, container, group


class NativePolicyValidator:
    """Evaluate the complete catalog without requiring external binaries."""

    name = "native_policy"

    def __init__(self, catalog: PolicyCatalog) -> None:
        self.catalog = catalog

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]:
        """Return deterministic findings for all supported resources."""
        started = perf_counter()
        findings: list[Finding] = []
        k8s = [
            resource for resource in resources if resource.ref.source != SourceType.TERRAFORM_PLAN
        ]
        terraform = [
            resource for resource in resources if resource.ref.source == SourceType.TERRAFORM_PLAN
        ]
        for resource in k8s:
            findings.extend(self._kubernetes(resource))
        findings.extend(self._network_policy_coverage(k8s))
        findings.extend(self._terraform(terraform))
        elapsed = (perf_counter() - started) * 1000
        return findings, ValidatorRun(
            name=self.name,
            duration_ms=elapsed,
            resources_checked=len(resources),
            findings=len(findings),
        )

    def _finding(
        self,
        policy_id: str,
        resource: Resource,
        message: str,
        path: str | None = None,
        validator: str = "conftest",
    ) -> Finding:
        policy = self.catalog.get(policy_id)
        return Finding.create(
            policy_id=policy.id,
            title=policy.title,
            severity=policy.severity,
            category=policy.category,
            resource=resource.ref,
            message=message,
            remediation=policy.remediation,
            path=path,
            validator=validator,
        )

    def _kubernetes(self, resource: Resource) -> list[Finding]:
        raw, kind = resource.raw, resource.ref.kind
        output: list[Finding] = []
        if kind == "Service":
            service_type = raw.get("spec", {}).get("type", "ClusterIP")
            approved = (
                raw.get("metadata", {})
                .get("annotations", {})
                .get("infraguard.io/exposure-approved")
                == "true"
            )
            if service_type in {"LoadBalancer", "NodePort"} and not approved:
                output.append(
                    self._finding(
                        "K8S-NET-001",
                        resource,
                        f"{service_type} service without exposure approval",
                        "spec.type",
                    )
                )
            return output
        if kind not in WORKLOADS:
            return output
        spec = _pod_spec(raw)
        pod_security = spec.get("securityContext") or {}
        for field in ("hostNetwork", "hostPID", "hostIPC"):
            if spec.get(field) is True:
                output.append(
                    self._finding(
                        "K8S-SEC-003",
                        resource,
                        f"{field} is enabled",
                        f"spec.template.spec.{field}",
                    )
                )
                break
        if any("hostPath" in volume for volume in spec.get("volumes") or []):
            output.append(
                self._finding(
                    "K8S-SEC-004",
                    resource,
                    "workload uses a hostPath volume",
                    "spec.template.spec.volumes",
                )
            )
        for index, container, group in _containers(spec):
            prefix = f"spec.template.spec.{group}[{index}]"
            name = container.get("name", f"{group}[{index}]")
            security = container.get("securityContext") or {}
            if security.get("privileged") is True:
                output.append(
                    self._finding(
                        "K8S-SEC-001",
                        resource,
                        f"container '{name}' runs privileged",
                        f"{prefix}.securityContext.privileged",
                    )
                )
            nonroot = security.get("runAsNonRoot", pod_security.get("runAsNonRoot")) is True
            user = security.get("runAsUser", pod_security.get("runAsUser"))
            if not nonroot or user == 0:
                output.append(
                    self._finding(
                        "K8S-SEC-002",
                        resource,
                        f"container '{name}' may run as root",
                        f"{prefix}.securityContext.runAsNonRoot",
                    )
                )
            if security.get("allowPrivilegeEscalation") is not False:
                output.append(
                    self._finding(
                        "K8S-SEC-005",
                        resource,
                        f"container '{name}' allows privilege escalation",
                        f"{prefix}.securityContext.allowPrivilegeEscalation",
                    )
                )
            added = set((security.get("capabilities") or {}).get("add") or []) & DANGEROUS_CAPS
            if added:
                output.append(
                    self._finding(
                        "K8S-SEC-006",
                        resource,
                        f"container '{name}' adds {', '.join(sorted(added))}",
                        f"{prefix}.securityContext.capabilities.add",
                    )
                )
            if security.get("readOnlyRootFilesystem") is not True:
                output.append(
                    self._finding(
                        "K8S-SEC-007",
                        resource,
                        f"container '{name}' has a writable root filesystem",
                        f"{prefix}.securityContext.readOnlyRootFilesystem",
                    )
                )
            resources = container.get("resources") or {}
            requests, limits = resources.get("requests") or {}, resources.get("limits") or {}
            if not all((requests.get("cpu"), requests.get("memory"), limits.get("memory"))):
                output.append(
                    self._finding(
                        "K8S-REL-001",
                        resource,
                        f"container '{name}' is missing resource requests or limits",
                        f"{prefix}.resources",
                    )
                )
            image = str(container.get("image", ""))
            if "@sha256:" not in image and (
                ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")
            ):
                output.append(
                    self._finding(
                        "K8S-REL-002",
                        resource,
                        f"container '{name}' uses mutable image '{image}'",
                        f"{prefix}.image",
                    )
                )
            if kind in CONTROLLERS_WITH_PROBES and (
                not container.get("livenessProbe") or not container.get("readinessProbe")
            ):
                output.append(
                    self._finding(
                        "K8S-REL-003",
                        resource,
                        f"container '{name}' is missing liveness or readiness probe",
                        prefix,
                    )
                )
        if (
            kind == "Deployment"
            and raw.get("metadata", {}).get("labels", {}).get("infraguard.io/tier") == "prod"
            and (raw.get("spec", {}).get("replicas", 1) < 2)
        ):
            output.append(
                self._finding(
                    "K8S-REL-004",
                    resource,
                    "production Deployment has fewer than two replicas",
                    "spec.replicas",
                )
            )
        return output

    def _network_policy_coverage(self, resources: list[Resource]) -> list[Finding]:
        workloads: dict[str, Resource] = {}
        protected = {
            resource.ref.namespace for resource in resources if resource.ref.kind == "NetworkPolicy"
        }
        for resource in resources:
            if resource.ref.kind in WORKLOADS and resource.ref.namespace:
                workloads.setdefault(resource.ref.namespace, resource)
        return [
            self._finding(
                "K8S-NET-002",
                resource,
                f"namespace '{namespace}' has workloads but no NetworkPolicy",
                "metadata.namespace",
                "python",
            )
            for namespace, resource in workloads.items()
            if namespace not in protected
        ]

    def _terraform(self, resources: list[Resource]) -> list[Finding]:
        output: list[Finding] = []
        by_type: dict[str, list[Resource]] = {}
        for resource in resources:
            by_type.setdefault(resource.ref.kind, []).append(resource)
        buckets = by_type.get("aws_s3_bucket", [])
        access_blocks = by_type.get("aws_s3_bucket_public_access_block", [])
        encryptions = by_type.get("aws_s3_bucket_server_side_encryption_configuration", [])
        versions = by_type.get("aws_s3_bucket_versioning", [])
        for resource in resources:
            change = resource.raw.get("change", {})
            after = change.get("after") or {}
            actions = change.get("actions") or []
            if "delete" in actions:
                verb = "replace" if "create" in actions else "delete"
                output.append(
                    self._finding(
                        "TF-PLAN-001",
                        resource,
                        f"plan will {verb} {resource.ref.address}",
                        "change.actions",
                        "terraform_analyzer",
                    )
                )
                if resource.ref.kind in STATEFUL_TYPES:
                    output.append(
                        self._finding(
                            "TF-PLAN-002",
                            resource,
                            f"stateful resource will be {verb}d",
                            "change.actions",
                            "terraform_analyzer",
                        )
                    )
            if resource.ref.kind in {
                "aws_security_group",
                "aws_security_group_rule",
                "aws_vpc_security_group_ingress_rule",
            }:
                ingress = after.get(
                    "ingress",
                    [after] if after.get("type") == "ingress" or "cidr_ipv4" in after else [],
                )
                for rule in ingress or []:
                    cidrs = list(rule.get("cidr_blocks") or []) + list(
                        rule.get("ipv6_cidr_blocks") or []
                    )
                    cidrs += [rule.get("cidr_ipv4"), rule.get("cidr_ipv6")]
                    world = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)
                    low, high = rule.get("from_port", 0), rule.get("to_port", 0)
                    if world and (
                        rule.get("protocol") == "-1"
                        or (rule.get("protocol") == "tcp" and low <= 22 <= high)
                    ):
                        output.append(
                            self._finding(
                                "TF-AWS-NET-001",
                                resource,
                                "SSH ingress is open to the world",
                                "change.after.ingress",
                            )
                        )
                    if world and (rule.get("protocol") == "-1" or (low == 0 and high == 65535)):
                        output.append(
                            self._finding(
                                "TF-AWS-NET-002",
                                resource,
                                "all ports are open to the world",
                                "change.after.ingress",
                            )
                        )
            if resource.ref.kind in {"aws_iam_policy", "aws_iam_role_policy"}:
                document = after.get("policy")
                try:
                    policy = json.loads(document) if isinstance(document, str) else document or {}
                except json.JSONDecodeError:
                    policy = {}
                if any(
                    statement.get("Effect") == "Allow"
                    and (statement.get("Action") == "*" or "*" in (statement.get("Action") or []))
                    and (
                        statement.get("Resource") == "*" or "*" in (statement.get("Resource") or [])
                    )
                    for statement in policy.get("Statement", [])
                ):
                    output.append(
                        self._finding(
                            "TF-AWS-IAM-001",
                            resource,
                            "IAM policy allows wildcard action and resource",
                            "change.after.policy",
                        )
                    )
        for bucket in buckets:
            if bucket.raw.get("change", {}).get("after") is None:
                continue
            bucket_id = (bucket.raw.get("change", {}).get("after") or {}).get("bucket")

            def matches(
                candidate: Resource,
                expected: Any = bucket_id,
                address: str | None = bucket.ref.address,
            ) -> bool:
                after = candidate.raw.get("change", {}).get("after")
                if after is None:
                    return False
                value = after.get("bucket")
                references = candidate.raw.get("_references", {}).get("bucket", [])
                return (value is not None and value in {expected, address}) or any(
                    ref == address or ref.startswith(f"{address}.") for ref in references
                )

            blocks = [item for item in access_blocks if matches(item)]
            public = not blocks or any(
                not all(
                    (item.raw.get("change", {}).get("after") or {}).get(flag) is True
                    for flag in (
                        "block_public_acls",
                        "block_public_policy",
                        "ignore_public_acls",
                        "restrict_public_buckets",
                    )
                )
                for item in blocks
            )
            if public:
                output.append(
                    self._finding(
                        "TF-AWS-S3-001",
                        bucket,
                        "bucket does not block all public access",
                        "change.after",
                    )
                )
            if not any(matches(item) for item in encryptions):
                output.append(
                    self._finding(
                        "TF-AWS-S3-002",
                        bucket,
                        "bucket has no server-side encryption configuration",
                        "change.after",
                    )
                )
            if not any(
                matches(item)
                and (item.raw.get("change", {}).get("after") or {})
                .get("versioning_configuration", [{}])[0]
                .get("status")
                == "Enabled"
                for item in versions
            ):
                output.append(
                    self._finding(
                        "TF-AWS-S3-003", bucket, "bucket versioning is not enabled", "change.after"
                    )
                )
        return output
