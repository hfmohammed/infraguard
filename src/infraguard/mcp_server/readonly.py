"""Capability-limited Kubernetes client and filesystem path guard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from infraguard.errors import PathGuardError, ReadOnlyViolation


class ReadOnlyK8s:
    """Expose only list/read methods plus an explicitly dry-run apply callable."""

    def __init__(self, client: Any) -> None:
        self._client = client

    def __getattr__(self, name: str) -> Any:
        """Allow reads and lists; deny every other dynamic operation."""
        if name.startswith(("list_", "read_")):
            return getattr(self._client, name)
        raise ReadOnlyViolation(f"Kubernetes operation is not allowed: {name}")

    def dry_run_apply(self, method: str, **kwargs: Any) -> Any:
        """Call a patch method with mandatory server-side dry-run controls."""
        if method != "patch" and not method.startswith("patch_"):
            raise ReadOnlyViolation("dry-run apply requires a patch method")
        kwargs.update(dry_run="All", field_manager="infraguard")
        return getattr(self._client, method)(**kwargs)


def guarded_path(value: str | Path, allowed_root: Path) -> Path:
    """Resolve a path and require it to remain under the allowed root."""
    root = allowed_root.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise PathGuardError(f"path escapes allowed root: {value}") from error
    return resolved
