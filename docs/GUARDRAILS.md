# Guarded remediation

InfraGuard follows one rule: an AI may propose, the pipeline verifies, and a human decides.

1. Pydantic and identity checks reject retargeting, privileged object kinds, disallowed API versions, and oversized input.
2. kubeconform validates the Kubernetes schema.
3. Policy comparison requires the target finding to disappear without introducing a new finding.
4. Server-side dry-run asks Kubernetes to validate admission and immutability without persistence.
5. A human at an interactive terminal must type the exact resource name before apply.

Each executed step appends one JSON line to `audit/remediation.jsonl`. The log includes actor, context, result, target, proposer, and a SHA-256 digest; it never stores the manifest or secrets. MCP stops before approval and apply.

