"""Prometheus metrics for scan results."""

from pathlib import Path
from threading import Thread
from wsgiref.simple_server import WSGIServer

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
    start_http_server,
)

from infraguard.mcp_server.audit import CALLS
from infraguard.models import ScanReport
from infraguard.policies.catalog import PolicyCatalog
from infraguard.remediation.audit import PIPELINE


def registry_for(report: ScanReport) -> CollectorRegistry:
    """Build an isolated metrics registry for one scan."""
    registry = CollectorRegistry()
    registry.register(CALLS)
    registry.register(PIPELINE)
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
        "infraguard_resources_scanned_total",
        "Resources collected",
        ["source", "kind"],
        registry=registry,
    )
    duration = Histogram(
        "infraguard_scan_duration_seconds",
        "Scan phase latency",
        ["phase"],
        buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 30),
        registry=registry,
    )
    passed = Gauge("infraguard_last_scan_passed", "Whether the last scan passed", registry=registry)
    timestamp = Gauge(
        "infraguard_last_scan_timestamp_seconds", "Last scan completion", registry=registry
    )
    timestamp.set(report.finished_at.timestamp())
    loaded = Gauge("infraguard_policies_loaded", "Policies loaded", ["target"], registry=registry)
    for target in ("kubernetes", "terraform"):
        loaded.labels(target).set(sum(p.target == target for p in PolicyCatalog.load().all()))
    errors = Counter(
        "infraguard_validator_errors_total", "Validator failures", ["validator"], registry=registry
    )
    for execution in report.validators:
        errors.labels(execution.name).inc(1 if execution.error else 0)
    for finding in report.findings:
        violations.labels(
            finding.policy_id,
            finding.severity.value,
            finding.category.value,
            finding.resource.source.value,
        ).inc()
    for item in report.summary.by_severity.model_dump():
        severity.labels(item).set(getattr(report.summary.by_severity, item))
    if report.summary.resources_by_kind:
        for source, kinds in report.summary.resources_by_kind.items():
            for kind, count in kinds.items():
                resources.labels(source, kind).inc(count)
    else:
        for source, count in report.summary.resources_by_source.items():
            resources.labels(source, "unknown").inc(count)
    for phase, elapsed in report.phase_durations_ms.items():
        duration.labels(phase).observe(elapsed / 1000)
    duration.labels("total").observe(report.duration_ms / 1000)
    passed.set(1 if report.summary.passed else 0)
    return registry


def write_metrics(report: ScanReport, output: Path) -> None:
    """Write Prometheus text exposition."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(generate_latest(registry_for(report)))


def serve_metrics(
    report: ScanReport, *, port: int = 9108, host: str = "127.0.0.1"
) -> tuple[WSGIServer, Thread]:
    """Serve a scan snapshot; caller owns shutdown of the server and thread."""
    return start_http_server(port, addr=host, registry=registry_for(report))
