from datetime import UTC, datetime
from pathlib import Path

import pytest

from infraguard.models import ResourceRef, SourceType
from infraguard.remediation.approval import request_approval
from infraguard.remediation.audit import append_step
from infraguard.remediation.models import RemediationProposal
from infraguard.remediation.pipeline import validate_proposal


def proposal(**manifest_updates: object) -> RemediationProposal:
    manifest = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api", "namespace": "prod"},
        "spec": {},
    }
    manifest.update(manifest_updates)
    return RemediationProposal(
        proposal_id="123",
        finding_fingerprint="abc",
        policy_id="K8S-SEC-001",
        target=ResourceRef(
            source=SourceType.KUBERNETES_LIVE,
            kind="Deployment",
            name="api",
            namespace="prod",
        ),
        proposed_manifest=manifest,
        rationale="disable privileged mode",
        proposer="rule_based",
        created_at=datetime.now(UTC),
    )


def test_valid_proposal_passes_schema_gate() -> None:
    assert validate_proposal(proposal()).result == "pass"


def test_retargeted_proposal_fails_closed() -> None:
    item = proposal(metadata={"name": "other", "namespace": "prod"})
    assert validate_proposal(item).result == "fail"


def test_denied_kind_fails_closed() -> None:
    item = proposal(kind="Secret", apiVersion="v1")
    assert validate_proposal(item).result == "fail"


def test_noninteractive_approval_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(RuntimeError, match="interactive terminal"):
        request_approval("api")


def test_audit_contains_hash_not_manifest(tmp_path: Path) -> None:
    item = proposal()
    step = validate_proposal(item)
    path = tmp_path / "audit.jsonl"
    append_step(path, item, step)
    content = path.read_text()
    assert "manifest_sha256" in content
    assert "proposed_manifest" not in content
