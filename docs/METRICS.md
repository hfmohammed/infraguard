# Measured results

Measurements recorded locally on 2026-10-21 from the offline suite. Live cluster figures remain environment-dependent; no values are estimated.

| Metric | Measured value |
|---|---:|
| Policy catalog | 21 (13 Kubernetes, 8 Terraform) |
| Seeded policy coverage | 21/21 |
| Pytest cases | 137 unit passed; 10 cluster cases run separately in CI |
| Python test coverage | 86.83% with branch coverage enabled |
| Rego tests | 69 passed, including positive/negative control cases |
| Mixed seeded scan | 6 resources, 20 findings, all 19 applicable catalog controls detected |
| Real compliant Terraform plan | 6 resources, 0 findings; mock credentials, refresh disabled |
| Read-only MCP tools | 6 |
| Remediation proposal policies | 6 |
| Approval boundary | interactive TTY + exact resource name |

