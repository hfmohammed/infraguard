# Policy catalog

| ID | Severity | Title | Engine |
|---|---|---|---|
| K8S-NET-001 | HIGH | Externally exposed Service | conftest |
| K8S-NET-002 | MEDIUM | Namespace without a NetworkPolicy | python |
| K8S-REL-001 | MEDIUM | Missing resource requests/limits | conftest |
| K8S-REL-002 | MEDIUM | Mutable image tag | conftest |
| K8S-REL-003 | MEDIUM | Missing liveness/readiness probes | conftest |
| K8S-REL-004 | LOW | Single-replica Deployment in a prod tier | conftest |
| K8S-SEC-001 | CRITICAL | Privileged container | conftest |
| K8S-SEC-002 | HIGH | Container may run as root | conftest |
| K8S-SEC-003 | HIGH | Host namespaces enabled | conftest |
| K8S-SEC-004 | HIGH | hostPath volume | conftest |
| K8S-SEC-005 | MEDIUM | Privilege escalation allowed | conftest |
| K8S-SEC-006 | HIGH | Dangerous capabilities added | conftest |
| K8S-SEC-007 | LOW | Writable root filesystem | conftest |
| TF-AWS-IAM-001 | CRITICAL | Wildcard IAM policy | conftest |
| TF-AWS-NET-001 | CRITICAL | SSH open to the world | conftest |
| TF-AWS-NET-002 | HIGH | Unrestricted ingress on all ports | conftest |
| TF-AWS-S3-001 | CRITICAL | Public S3 bucket | conftest |
| TF-AWS-S3-002 | HIGH | Unencrypted S3 bucket | conftest |
| TF-AWS-S3-003 | LOW | Versioning disabled | conftest |
| TF-PLAN-001 | HIGH | Resource destroyed or replaced | terraform_analyzer |
| TF-PLAN-002 | CRITICAL | Stateful resource replacement | terraform_analyzer |

## Evaluation notes

Normal scans combine kubeconform, Conftest/Rego, and native inventory/action checks. `SCHEMA-001` is a schema diagnostic, separate from the 21 catalog controls.

S3 companion resources join by known bucket names or by Terraform configuration references when planned IDs are unknown. The collector retains only those references and removes configuration constants and variables from the redacted plan. Deleted companion resources do not satisfy a protective control.

NetworkPolicy coverage means a policy exists in the namespace; it does not prove that its selectors and traffic rules protect every workload.

