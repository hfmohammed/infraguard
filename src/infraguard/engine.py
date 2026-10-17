"""Collection, validation, deterministic ordering, and summary orchestration."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from time import perf_counter
from typing import Literal
from uuid import uuid4

from infraguard import __version__
from infraguard.collectors.base import Collector
from infraguard.models import Finding, ScanReport, ScanSummary, Severity, SeveritySummary
from infraguard.policies.catalog import PolicyCatalog
from infraguard.validators.base import Validator


def finding_sort_key(finding: Finding) -> tuple[int, str, str, str]:
    """Return the canonical finding sort key."""
    return (-finding.severity.rank, finding.policy_id, finding.resource.key(), finding.path or "")


def run_scan(
    collectors: list[Collector],
    validators: list[Validator],
    fail_on: Severity | Literal["NONE"] = Severity.HIGH,
    catalog: PolicyCatalog | None = None,
) -> ScanReport:
    """Collect resources, run validators, and create an immutable report."""
    started_at = datetime.now(UTC)
    started = perf_counter()
    resources = [resource for collector in collectors for resource in collector.collect()]
    findings: list[Finding] = []
    runs = []
    for validator in validators:
        emitted, run = validator.validate(resources)
        findings.extend(emitted)
        runs.append(run)
    unique = {finding.fingerprint: finding for finding in findings}
    ordered = sorted(unique.values(), key=finding_sort_key)
    severity_counts = Counter(finding.severity.value for finding in ordered)
    source_counts = Counter(resource.ref.source.value for resource in resources)
    policy_counts = Counter(finding.policy_id for finding in ordered)
    passed = fail_on == "NONE" or not any(
        finding.severity.rank >= fail_on.rank for finding in ordered
    )
    summary = ScanSummary(
        resources_scanned=len(resources),
        resources_by_source=dict(sorted(source_counts.items())),
        findings_total=len(ordered),
        by_severity=SeveritySummary(**severity_counts),
        by_policy=dict(sorted(policy_counts.items())),
        policies_evaluated=len(catalog) if catalog else 0,
        passed=passed,
    )
    finished_at = datetime.now(UTC)
    return ScanReport(
        tool_version=__version__,
        scan_id=str(uuid4()),
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=(perf_counter() - started) * 1000,
        targets=[collector.describe_target() for collector in collectors],
        fail_on=fail_on,
        summary=summary,
        findings=ordered,
        validators=runs,
    )
