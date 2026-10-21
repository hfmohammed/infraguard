# Architecture

InfraGuard separates read-only acquisition, immutable normalized models, validation, and rendering. Collectors never make policy decisions; validators never acquire data; renderers receive a complete `ScanReport`. This makes offline and live scans behave identically and keeps tests deterministic.

The default validator registry runs kubeconform, Conftest/Rego, the cross-resource network check, and the Terraform action analyzer. `--offline` selects the built-in evaluator explicitly; failures never trigger an automatic fallback. Conftest receives individual Kubernetes documents and the complete Terraform change inventory. Configuration references are retained for joins when planned IDs are unknown. Findings use a stable fingerprint derived from policy, resource key, and field path, then sort by severity, policy, resource, and path.

Policy metadata and Rego files ship inside the wheel. Editable installs resolve them relative to the source package, never relative to the caller's working directory. Terraform subprocesses receive their own environment mapping and operate on a temporary module copy; they do not alter process-wide credentials.

Trust boundaries are narrow: Terraform runs only in a temporary copy, Kubernetes collection uses list/read calls, MCP confines file paths and strips secrets, and remediation is the only mutation-capable subsystem. A remediation requires target-bound input, schema and policy checks, server-side dry-run, and a real TTY approval.

