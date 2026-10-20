# Architecture

InfraGuard separates read-only acquisition, immutable normalized models, validation, and rendering. Collectors never make policy decisions; validators never acquire data; renderers receive a complete `ScanReport`. This makes offline and live scans behave identically and keeps tests deterministic.

The built-in evaluator provides a fast, dependency-free path for developer feedback. Conftest/Rego and kubeconform wrappers are explicit defense-in-depth adapters for CI and remediation gates. Findings use a stable fingerprint derived from policy, resource key, and field path, then sort by severity, policy, resource, and path.

Trust boundaries are narrow: Terraform runs only in a temporary copy, Kubernetes collection uses list/read calls, MCP confines file paths and strips secrets, and remediation is the only mutation-capable subsystem. A remediation requires target-bound input, schema and policy checks, server-side dry-run, and a real TTY approval.

