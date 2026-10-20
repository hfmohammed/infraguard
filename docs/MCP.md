# MCP server

Start the server with `infraguard mcp serve --context kind-infraguard`. It exposes exactly six tools: `list_cluster_resources`, `get_resource`, `get_policy_findings`, `analyze_terraform_plan`, `validate_manifest`, and `validate_patch`.

The Kubernetes wrapper permits `list_*` and `read_*` operations. The sole patch path forces `dry_run="All"`; mutation names are otherwise rejected. Paths are resolved below `--allowed-root`, YAML is limited to 256 KB and 50 documents, list responses are capped at 500, and all returned objects pass through redaction. `validate_patch` always reports `applied: false`.

The included RBAC role intentionally cannot read Secrets. Kubernetes authorizes server-side dry-run like a real patch, so patch RBAC is required only when enabling patch validation with a trusted context.

