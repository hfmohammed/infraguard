# Measured results

Measurements recorded locally on 2026-10-21 from the offline suite. Live cluster figures remain environment-dependent; no values are estimated.

| Metric | Measured value |
|---|---:|
| Policy catalog | 21 (13 Kubernetes, 8 Terraform) |
| Seeded policy coverage | 21/21 |
| Pytest cases | 153 unit cases; 12 cluster cases run separately in CI |
| Python test coverage | 86.76% with branch coverage enabled |
| Rego tests | 78 passed, including positive/negative control cases |
| Seeded precision / recall | 100% / 100%, exact expected policy/resource pairs |
| Mixed seeded scan | 6 resources, 20 findings, all 19 applicable catalog controls detected |
| Real compliant Terraform plan | 6 resources, 0 findings; mock credentials, refresh disabled |
| Read-only MCP tools | 6 |
| Remediation proposal policies | 6 |
| Approval boundary | interactive TTY + exact resource name |

## Policy gate evidence

[Controlled negative run](https://github.com/hfmohammed/infraguard/actions/runs/39558621483): the verification branch added `privileged: true` to the compliant Helm chart. Lint, both Python matrices, real Terraform plans, schema checks, and Rego tests passed; the **Gate compliant manifests and rendered Helm policies** step rejected `K8S-SEC-001` with exit 1. The change was reverted on the verification branch and never merged into `main`.

The tracked-artifact guard was also exercised with a harmless staged file named `tfplan` in an isolated worktree. `scripts/check_no_plans.sh` rejected it with exit 1; the probe was unstaged and removed without committing it.

## Successful live verification

[Successful ownership and safety run](https://github.com/hfmohammed/infraguard/actions/runs/39559416067) passed all five jobs, including the real Helm ownership-conflict test, the explicit ownership dry-run, immutable-selector rejection, all six MCP tools, and noninteractive apply refusal. Its measured workflow runtime was **3 minutes 25 seconds** (07:03:59–07:07:24 UTC). Later policy-boundary and report-golden tests extend that baseline.

