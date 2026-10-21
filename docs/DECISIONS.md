# Engineering decisions

- 2026-10-15: External binaries are optional for the native offline analyzer; strict wrappers remain available for parity with CI.
- 2026-10-15: Terraform execution uses a temporary working copy, mock AWS credentials, disabled validation, and never applies.
- 2026-10-15: Cluster integration tests skip locally when kind is absent and fail in CI when the declared cluster is absent.
- 2026-10-21: Schema and Rego validation are the default. The native evaluator requires `--offline`; missing tools never silently change validation mode.
- 2026-10-21: Wheels bundle the canonical policy directory; working-directory overrides require an explicit `--policy-dir`.
- 2026-10-21: Terraform joins use configuration references when resource IDs are unknown before apply. Only changes with non-null desired values satisfy protective controls.
- 2026-10-21: Both a TCP SSH range and world-open all-protocol ingress trigger SSH exposure. The seeded fixture therefore has two SSH findings and 20 total mixed findings.
- 2026-10-21: The document-count test now uses valid YAML separators (`\n---\n`); its previous separator produced malformed YAML rather than 51 documents.
- 2026-10-21: Remediation rejects redacted placeholders. Copying a redacted live manifest back to Kubernetes could otherwise overwrite sensitive environment values.
- 2026-10-21: Metrics serve a scan snapshot and process-local operation counters. They do not imply a periodic scanner or a durable aggregate across restarts.
- 2026-10-21: Helm field ownership conflicts stop remediation by default. An explicit `--take-ownership` option is required for the sample fix; dry-run and apply share that setting and the approval prompt discloses it. MCP simulates ownership transfer without persisting changes.
- 2026-10-21: Full Terraform plan access redacts planned/prior values and sensitive outputs, and drops configuration constants after extracting relationship references.

