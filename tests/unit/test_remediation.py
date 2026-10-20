from datetime import UTC, datetime
from pathlib import Path

import pytest

from infraguard.errors import ToolError
from infraguard.models import Resource, ResourceRef, SourceType, ValidatorRun
from infraguard.remediation.approval import request_approval
from infraguard.remediation.audit import append_step
from infraguard.remediation.models import PipelineResult, RemediationProposal, StepResult
from infraguard.remediation.pipeline import (
    MAX_MANIFEST_BYTES,
    apply_proposal,
    check_proposal,
    validate_manifest_size_and_count,
    validate_proposal,
)
from infraguard.validators.native import NativePolicyValidator


@pytest.fixture(autouse=True)
def isolated_policy_tool(monkeypatch):
    # Unit tests exercise pipeline decisions; external Rego parity is tested separately.
    monkeypatch.setattr("infraguard.remediation.pipeline.ConftestValidator", NativePolicyValidator)


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


def test_schema_gate_reports_identity_allowlist_and_size_errors() -> None:
    item = proposal(
        apiVersion="example.invalid/v1",
        kind="StatefulSet",
        metadata={"name": "api", "namespace": "other"},
        oversized="x" * MAX_MANIFEST_BYTES,
    ).model_copy(
        update={
            "target": ResourceRef(
                source=SourceType.MANIFEST,
                kind="Deployment",
                name="api",
                namespace="prod",
            )
        }
    )
    result = validate_proposal(item)
    assert result.result == "fail"
    assert result.detail is not None
    assert "target source" in result.detail
    assert "kind does not match" in result.detail
    assert "namespace does not match" in result.detail
    assert "apiVersion is not allowed" in result.detail
    assert "manifest exceeds 256 KB" in result.detail


def test_manifest_input_size_limit() -> None:
    with pytest.raises(ValueError, match="256 KB"):
        validate_manifest_size_and_count("x" * (MAX_MANIFEST_BYTES + 1))


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


def test_check_pipeline_runs_all_nonmutating_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = proposal()
    live = Resource(
        ref=item.target,
        raw=item.proposed_manifest,
        collected_at=datetime.now(UTC),
    )
    monkeypatch.setattr(
        "infraguard.remediation.pipeline.KubeconformValidator.validate",
        lambda self, resources: (
            [],
            ValidatorRun(
                name="kubeconform",
                duration_ms=0,
                resources_checked=1,
                findings=0,
            ),
        ),
    )
    monkeypatch.setattr("infraguard.remediation.pipeline._find_live_resource", lambda *args: live)
    monkeypatch.setattr(
        "infraguard.remediation.pipeline._server_side_apply",
        lambda *args, **kwargs: item.proposed_manifest,
    )
    result = check_proposal(item, audit_path=tmp_path / "audit.jsonl")
    assert [step.step for step in result.steps] == [
        "schema",
        "kubeconform",
        "conftest",
        "dry_run",
    ]
    assert all(step.result == "pass" for step in result.steps)
    assert result.applied is False
    assert len((tmp_path / "audit.jsonl").read_text().splitlines()) == 4


def test_check_pipeline_records_kubeconform_tool_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unavailable(*args: object, **kwargs: object) -> None:
        raise ToolError("kubeconform failed")

    monkeypatch.setattr(
        "infraguard.remediation.pipeline.KubeconformValidator.validate", unavailable
    )
    result = check_proposal(proposal(), audit_path=tmp_path / "audit.jsonl")
    assert [step.step for step in result.steps] == ["schema", "kubeconform"]
    assert result.steps[-1].result == "fail"
    assert result.steps[-1].detail == "kubeconform failed"


def test_check_pipeline_records_server_dry_run_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = proposal()
    live = Resource(ref=item.target, raw=item.proposed_manifest, collected_at=datetime.now(UTC))
    monkeypatch.setattr(
        "infraguard.remediation.pipeline.KubeconformValidator.validate",
        lambda self, resources: (
            [],
            ValidatorRun(name="kubeconform", duration_ms=0, resources_checked=1, findings=0),
        ),
    )
    monkeypatch.setattr("infraguard.remediation.pipeline._find_live_resource", lambda *args: live)

    def reject_dry_run(*args: object, **kwargs: object) -> None:
        raise RuntimeError("admission webhook denied the patch")

    monkeypatch.setattr("infraguard.remediation.pipeline._server_side_apply", reject_dry_run)
    result = check_proposal(item, audit_path=tmp_path / "audit.jsonl")
    assert result.steps[-1].step == "dry_run"
    assert result.steps[-1].result == "fail"
    assert "admission webhook" in (result.steps[-1].detail or "")


def test_apply_pipeline_mutates_only_after_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = proposal()
    live = Resource(
        ref=item.target,
        raw=item.proposed_manifest,
        collected_at=datetime.now(UTC),
    )
    monkeypatch.setattr(
        "infraguard.remediation.pipeline.KubeconformValidator.validate",
        lambda self, resources: (
            [],
            ValidatorRun(
                name="kubeconform",
                duration_ms=0,
                resources_checked=1,
                findings=0,
            ),
        ),
    )
    monkeypatch.setattr("infraguard.remediation.pipeline._find_live_resource", lambda *args: live)
    calls: list[bool] = []

    def server_apply(*args: object, dry_run: bool, **kwargs: object) -> dict[str, object]:
        calls.append(dry_run)
        return item.proposed_manifest

    monkeypatch.setattr("infraguard.remediation.pipeline._server_side_apply", server_apply)
    monkeypatch.setattr("infraguard.remediation.pipeline.request_approval", lambda name: True)
    result = apply_proposal(item, audit_path=tmp_path / "audit.jsonl")
    assert calls == [True, False]
    assert result.applied is True
    assert result.steps[-2].result == "approved"
    assert result.steps[-1].step == "apply"


def test_apply_pipeline_honors_rejected_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = proposal()
    checked = PipelineResult(
        proposal_id=item.proposal_id,
        steps=[StepResult(step="dry_run", result="pass", duration_ms=0)],
        applied=False,
    )
    monkeypatch.setattr("infraguard.remediation.pipeline.check_proposal", lambda *a, **k: checked)
    monkeypatch.setattr("infraguard.remediation.pipeline.request_approval", lambda name: False)
    result = apply_proposal(item, audit_path=tmp_path / "audit.jsonl")
    assert result.applied is False
    assert result.steps[-1].result == "rejected"


def test_apply_pipeline_records_apply_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    item = proposal()
    checked = PipelineResult(
        proposal_id=item.proposal_id,
        steps=[StepResult(step="dry_run", result="pass", duration_ms=0)],
        applied=False,
    )
    monkeypatch.setattr("infraguard.remediation.pipeline.check_proposal", lambda *a, **k: checked)
    monkeypatch.setattr("infraguard.remediation.pipeline.request_approval", lambda name: True)

    def fail_apply(*args: object, **kwargs: object) -> None:
        raise RuntimeError("conflict")

    monkeypatch.setattr("infraguard.remediation.pipeline._server_side_apply", fail_apply)
    result = apply_proposal(item, audit_path=tmp_path / "audit.jsonl")
    assert result.applied is False
    assert result.steps[-1].result == "fail"
    assert result.steps[-1].detail == "conflict"
