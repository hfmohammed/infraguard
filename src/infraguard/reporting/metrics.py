"""Prometheus metrics for scan results."""

from pathlib import Path

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from infraguard.models import ScanReport


def registry_for(report: ScanReport) -> CollectorRegistry:
    """Build an isolated metrics registry for one scan."""
    registry = CollectorRegistry()
    violations = Counter(
        "infraguard_policy_violations_total",
        "Findings emitted",
        ["policy_id", "severity", "category", "source"],
        registry=registry,
    )
    severity = Gauge(
        "infraguard_findings_by_severity",
        "Findings in latest scan",
        ["severity"],
        registry=registry,
    )
    resources = Counter(
        "infraguard_resources_scanned_total", "Resources collected", ["source"], registry=registry
    )
    duration = Histogram(
        "infraguard_scan_duration_seconds",
        "Scan phase latency",
        ["phase"],
        buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
        registry=registry,
    )
    passed = Gauge("infraguard_last_scan_passed", "Whether the last scan passed", registry=registry)
    for finding in report.findings:
        violations.labels(
            finding.policy_id,
            finding.severity.value,
            finding.category.value,
            finding.resource.source.value,
        ).inc()
    for item in report.summary.by_severity.model_dump():
        severity.labels(item).set(getattr(report.summary.by_severity, item))
    for source, count in report.summary.resources_by_source.items():
        resources.labels(source).inc(count)
    duration.labels("total").observe(report.duration_ms / 1000)
    passed.set(1 if report.summary.passed else 0)
    return registry


def write_metrics(report: ScanReport, output: Path) -> None:
    """Write Prometheus text exposition."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(generate_latest(registry_for(report)))
