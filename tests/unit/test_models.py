from datetime import UTC, datetime

from infraguard.models import Finding, Resource, ResourceRef, Severity, SourceType


def test_resource_keys_are_stable() -> None:
    ref = ResourceRef(source=SourceType.MANIFEST, kind="Deployment", name="api", namespace="prod")
    assert ref.key() == "prod/Deployment/api"


def test_terraform_address_is_the_key() -> None:
    ref = ResourceRef(
        source=SourceType.TERRAFORM_PLAN,
        kind="aws_s3_bucket",
        name="logs",
        address="aws_s3_bucket.logs",
    )
    assert ref.key() == "aws_s3_bucket.logs"


def test_resource_is_immutable() -> None:
    resource = Resource(
        ref=ResourceRef(source=SourceType.MANIFEST, kind="Pod", name="api"),
        raw={},
        collected_at=datetime.now(UTC),
    )
    assert resource.ref.name == "api"


def test_severity_rank() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.LOW.rank


def test_fingerprint_is_deterministic(finding_values: dict[str, object]) -> None:
    first = Finding.create(**finding_values)
    second = Finding.create(**finding_values)
    assert first.fingerprint == second.fingerprint
