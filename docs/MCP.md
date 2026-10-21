# MCP server

Start the server with `infraguard mcp serve --context kind-infraguard`. It exposes exactly six tools: `list_cluster_resources`, `get_resource`, `get_policy_findings`, `analyze_terraform_plan`, `validate_manifest`, and `validate_patch`.

The Kubernetes wrapper permits `list_*` and `read_*` operations. The sole patch path forces `dry_run="All"`; mutation names are otherwise rejected. Paths are resolved below `--allowed-root`, YAML is limited to 256 KB and 50 documents, list responses are capped at 500, and all returned objects pass through redaction. `validate_patch` always reports `applied: false`.

The included RBAC role intentionally cannot read Secrets. Kubernetes authorizes server-side dry-run like a real patch, so patch RBAC is required only when enabling patch validation with a trusted context.

Manifest validation runs kubeconform and Conftest. Patch validation runs the same technical gates as `remediate check`, including a live policy comparison and server-side dry-run, and returns the diff. No MCP tool calls `apply_proposal` or requests approval.

Every invocation appends `{ts, tool, args_sha256, result, duration_ms}` to `audit/mcp-calls.jsonl` under the allowed root. The `infraguard_mcp_tool_calls_total` counter records outcomes in this process. Arguments, responses, and exception messages are excluded from call records. Audit files are local append-only evidence, not a tamper-resistant centralized log.

