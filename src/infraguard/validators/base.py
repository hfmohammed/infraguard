"""Validator protocol."""

from typing import Protocol, runtime_checkable

from infraguard.models import Finding, Resource, ValidatorRun


@runtime_checkable
class Validator(Protocol):
    """A policy or schema validator."""

    name: str

    def validate(self, resources: list[Resource]) -> tuple[list[Finding], ValidatorRun]: ...

