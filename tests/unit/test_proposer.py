from datetime import UTC, datetime

import pytest

from infraguard.models import (
    Category,
    Finding,
    Resource,
    ResourceRef,
    Severity,
    SourceType,
)
from infraguard.remediation.proposer import propose, strip_server_fields


def live_resource() -> Resource:
    ref = ResourceRef(
        source=SourceType.KUBERNETES_LIVE,
        kind="Deployment",
        name="api",
        namespace="prod",
    )
    return Resource(
        ref=ref,
        raw={
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "api",
                "namespace": "prod",
                "resourceVersion": "123",
                "uid": "abc",
            },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "app",
                                "image": "app:1.0",
                                "ports": [{"containerPort": 8080}],
                                "securityContext": {"privileged": True},
                            }
                        ]
                    }
                }
            },
            "status": {"readyReplicas": 1},
        },
        collected_at=datetime.now(UTC),
    )


def finding(policy_id: str, resource: Resource) -> Finding:
    return Finding.create(
        policy_id=policy_id,
        title="policy",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        resource=resource.ref,
        message="unsafe",
        remediation="fix it",
        validator="python",
    )


@pytest.mark.parametrize(
    "policy_id",
    [
        "K8S-SEC-001",
        "K8S-SEC-002",
        "K8S-SEC-005",
        "K8S-SEC-007",
        "K8S-REL-001",
        "K8S-REL-003",
    ],
)
def test_supported_policies_produce_bound_proposals(policy_id: str) -> None:
    resource = live_resource()
    proposal = propose(finding(policy_id, resource), resource)
    assert proposal.policy_id == policy_id
    assert proposal.target == resource.ref
    assert "status" not in proposal.proposed_manifest
    assert "resourceVersion" not in proposal.proposed_manifest["metadata"]


def test_unknown_policy_is_rejected() -> None:
    resource = live_resource()
    with pytest.raises(ValueError, match="no deterministic remediation"):
        propose(finding("K8S-NET-001", resource), resource)


def test_nonlive_resource_is_rejected() -> None:
    resource = live_resource().model_copy(
        update={"ref": live_resource().ref.model_copy(update={"source": SourceType.MANIFEST})}
    )
    with pytest.raises(ValueError, match="live Kubernetes"):
        propose(finding("K8S-SEC-001", resource), resource)


def test_strip_server_fields_preserves_input() -> None:
    source = live_resource().raw
    cleaned = strip_server_fields(source)
    assert "status" not in cleaned
    assert "status" in source
