from pathlib import Path

import pytest

from infraguard.errors import PathGuardError, ReadOnlyViolation
from infraguard.mcp_server.readonly import ReadOnlyK8s, guarded_path


class DummyClient:
    def list_pod(self) -> list[str]:
        return ["pod"]

    def delete_pod(self) -> None:
        raise AssertionError("must not be called")

    def patch_pod(self, **kwargs: object) -> dict[str, object]:
        return kwargs


def test_read_only_wrapper_allows_lists() -> None:
    assert ReadOnlyK8s(DummyClient()).list_pod() == ["pod"]


@pytest.mark.parametrize("method", ["create_pod", "patch_pod", "replace_pod", "delete_pod"])
def test_read_only_wrapper_blocks_mutations(method) -> None:
    with pytest.raises(ReadOnlyViolation):
        getattr(ReadOnlyK8s(DummyClient()), method)()


def test_dry_run_is_forced() -> None:
    result = ReadOnlyK8s(DummyClient()).dry_run_apply(
        "patch_pod", body={}, dry_run=None, field_manager="untrusted"
    )
    assert result["dry_run"] == "All"
    assert result["field_manager"] == "infraguard"


def test_path_guard_blocks_escape(tmp_path: Path) -> None:
    with pytest.raises(PathGuardError):
        guarded_path("../escape.json", tmp_path)


def test_path_guard_accepts_nested_file(tmp_path: Path) -> None:
    nested = tmp_path / "plans" / "plan.json"
    nested.parent.mkdir()
    nested.write_text("{}")
    assert guarded_path("plans/plan.json", tmp_path) == nested


def test_path_guard_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (root / "linked.json").symlink_to(outside)
    with pytest.raises(PathGuardError):
        guarded_path("linked.json", root)
