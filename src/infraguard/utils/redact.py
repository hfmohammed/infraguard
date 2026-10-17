"""Recursive secret redaction used at all trust boundaries."""

from __future__ import annotations

import copy
import re
from typing import Any

SECRET_NAME = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)")


def redact_manifest(value: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied manifest with Kubernetes secret values removed."""
    result = copy.deepcopy(value)
    if result.get("kind") == "Secret":
        result.pop("data", None)
        result.pop("stringData", None)
    _redact_env(result)
    return result


def _redact_env(value: Any) -> None:
    if isinstance(value, dict):
        if SECRET_NAME.search(str(value.get("name", ""))) and "value" in value:
            value["value"] = "***REDACTED***"
        for child in value.values():
            _redact_env(child)
    elif isinstance(value, list):
        for child in value:
            _redact_env(child)


def redact_sensitive(value: Any, sensitive: Any) -> Any:
    """Replace Terraform values whose parallel sensitivity tree is true."""
    if sensitive is True:
        return "***REDACTED***"
    if isinstance(value, dict) and isinstance(sensitive, dict):
        return {
            key: redact_sensitive(item, sensitive.get(key, False)) for key, item in value.items()
        }
    if isinstance(value, list) and isinstance(sensitive, list):
        return [
            redact_sensitive(item, sensitive[i] if i < len(sensitive) else False)
            for i, item in enumerate(value)
        ]
    return copy.deepcopy(value)
