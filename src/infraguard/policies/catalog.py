"""Policy metadata catalog."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import TypeAdapter

from infraguard.errors import PolicyCatalogError
from infraguard.models import PolicyMeta


class PolicyCatalog:
    """Validated, indexed policy metadata."""

    def __init__(self, policies: list[PolicyMeta]) -> None:
        self._policies = policies
        self._by_id = {policy.id: policy for policy in policies}
        if len(self._by_id) != len(policies):
            raise PolicyCatalogError("policy IDs must be unique")

    @classmethod
    def load(cls, path: Path | None = None) -> PolicyCatalog:
        """Load metadata from YAML."""
        path = path or policy_directory() / "metadata.yaml"
        try:
            raw = yaml.safe_load(path.read_text())
            return cls(TypeAdapter(list[PolicyMeta]).validate_python(raw))
        except (OSError, ValueError) as error:
            raise PolicyCatalogError(f"cannot load policy catalog: {error}") from error

    def all(self) -> list[PolicyMeta]:
        """Return policies sorted by identifier."""
        return sorted(self._policies, key=lambda policy: policy.id)

    def get(self, policy_id: str) -> PolicyMeta:
        """Return metadata for an identifier or fail closed."""
        try:
            return self._by_id[policy_id]
        except KeyError as error:
            raise PolicyCatalogError(f"unknown policy ID: {policy_id}") from error

    def __len__(self) -> int:
        return len(self._policies)


def policy_directory() -> Path:
    """Locate shipped policies in a wheel or an editable source checkout."""
    package = Path(__file__).resolve().parents[1]
    bundled = package / "policy_data"
    return bundled if bundled.is_dir() else package.parents[1] / "policies"
