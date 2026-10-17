"""Collector interface."""

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from infraguard.models import Resource, SourceType


@runtime_checkable
class Collector(Protocol):
    """A read-only source of normalized resources."""

    name: str
    source: SourceType

    def collect(self) -> Iterable[Resource]: ...

    def describe_target(self) -> str: ...
