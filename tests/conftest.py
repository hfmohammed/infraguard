from pathlib import Path

import pytest

from infraguard.models import Category, ResourceRef, Severity, SourceType


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def finding_values() -> dict[str, object]:
    return {
        "policy_id": "K8S-SEC-001",
        "title": "Privileged container",
        "severity": Severity.CRITICAL,
        "category": Category.SECURITY,
        "resource": ResourceRef(
            source=SourceType.MANIFEST, kind="Pod", name="api", namespace="prod"
        ),
        "message": "container runs privileged",
        "remediation": "Disable privileged mode",
        "path": "spec.containers[0].securityContext.privileged",
        "validator": "python",
    }
