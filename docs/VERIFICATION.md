# Verification

The Python unit suite is independent of external binaries. Tool and cluster checks run in separate CI stages so a mocked unit test cannot stand in for an integration result.

| Requirement | Evidence |
|---|---|
| Deterministic findings and schema-backed JSON | `tests/unit/test_engine_reporting.py`, committed JSON Schema |
| All 21 policy controls seeded | `tests/unit/test_policy_matrix.py`, native detection tests, Rego positive/negative control tests |
| Strict schema and Rego validation | `validators/registry.py`, Conftest protocol tests, real CLI checks in `validate-iac` |
| Real Terraform plans without applying | `validate-iac` scans both root modules with mock credentials and refresh disabled |
| Installed package works outside the repo | Wheel build/install smoke test in each Python matrix job |
| Metrics file and HTTP endpoint | `test_metrics_are_available_over_http`, integration report artifacts |
| Live inventory and clean/seeded policy gates | `tests/integration/test_kind_collector.py`, `test_live_policy_accuracy` |
| Exactly six MCP tools and blocked mutations | Tool registry tests, capability-wrapper tests, six-tool kind exercise |
| Patch validation cannot persist changes | Kind tests compare Deployment resource versions before and after dry-run |
| Stop at the first failing remediation gate | Six parametrized live cases: good patch and five bad patches |
| Noninteractive apply is rejected | Real gate checks followed by CLI exit 4 against kind |
| Exact-name interactive approval | TTY boundary unit tests; apply-order tests with a fake mutation adapter |
| Content-free audit records | MCP hash/outcome tests and ordered remediation records |

## Reproduce locally

```bash
make setup
make lint
make test
make validate
make cluster-up
make deploy-samples
make test-integration
```

Local cluster tests skip if kind is unavailable; CI treats an unavailable cluster as a failure. The full validation path requires the pinned binaries and access to upstream schema/provider downloads. `--offline` omits external validation and is clearly identified in report validator names.

## Manual approval exercise

The automated cluster tests intentionally do not simulate a human authorizing a real mutation. In a terminal, inspect and run:

```bash
infraguard remediate check samples/remediation/good-patch.yaml --context kind-infraguard --take-ownership
infraguard remediate apply samples/remediation/good-patch.yaml --context kind-infraguard --take-ownership
```

Review the context and diff, then type `vulnerable-app` to approve. A re-scan of `ig-noncompliant` should no longer report `K8S-SEC-001`; other deliberately seeded controls still fail. `make deploy-samples` restores the original workload. Approval must be supplied by the operator; there is no unattended approval flag.

Helm owns the seeded fields. Transferring those fields requires `--take-ownership`, which is shown in the approval screen and audit record. A separate integration test proves that ownership conflicts stop the default path. MCP simulates the transfer only in a dry-run, returns `ownership_transfer: true`, and directs the human to the explicit CLI option.

## Limits

The bundled policy fixtures measure detection of known seeded cases, not accuracy over arbitrary production infrastructure. NetworkPolicy coverage checks for a policy in the namespace; it does not prove that selectors or traffic rules are sufficient. Terraform checks cover the supported AWS resource shapes. Audit logs are append-only files and can be changed by their filesystem owner. Local scan counters reset between processes.
