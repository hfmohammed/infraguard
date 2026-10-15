# Engineering decisions

- 2026-10-15: External binaries are optional for the native offline analyzer; strict wrappers remain available for parity with CI.
- 2026-10-15: Terraform execution uses a temporary working copy, mock AWS credentials, disabled validation, and never applies.
- 2026-10-15: Cluster integration tests skip locally when kind is absent and fail in CI when the declared cluster is absent.

