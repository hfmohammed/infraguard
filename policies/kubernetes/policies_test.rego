package infraguard.kubernetes

privileged := {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"bad"}, "spec":{"containers":[{"name":"app", "image":"app:1", "securityContext":{"privileged":true}}]}}
safe := {"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"safe"}, "spec":{"securityContext":{"runAsNonRoot":true}, "containers":[{"name":"app", "image":"app:1", "securityContext":{"privileged":false, "allowPrivilegeEscalation":false, "readOnlyRootFilesystem":true}, "resources":{"requests":{"cpu":"1", "memory":"1Mi"}, "limits":{"memory":"1Mi"}}}]}}

test_privileged_denied { count(deny) > 0 with input as privileged }
test_safe_not_privileged { not deny[message("K8S-SEC-001", "x", "y")] with input as safe }
test_workload_pod { workload_kind with input as privileged }
test_container_helper { count(all_containers) == 1 with input as privileged }
test_message_json { contains(message("ID", "msg", "path"), "ID") }
test_cap_sys_admin { dangerous_capability("SYS_ADMIN") }
test_cap_net_admin { dangerous_capability("NET_ADMIN") }
test_cap_net_raw { dangerous_capability("NET_RAW") }
test_cap_all { dangerous_capability("ALL") }
test_cap_safe { not dangerous_capability("CHOWN") }
test_safe_document { count(deny) == 0 with input as safe }
test_nodeport_denied { count(deny) > 0 with input as {"kind":"Service", "metadata":{}, "spec":{"type":"NodePort"}} }
test_clusterip_allowed { count(deny) == 0 with input as {"kind":"Service", "metadata":{}, "spec":{"type":"ClusterIP"}} }
test_prod_single_denied { count(deny) > 0 with input as {"kind":"Deployment", "metadata":{"labels":{"infraguard.io/tier":"prod"}}, "spec":{"replicas":1, "template":{"spec":{"containers":[]}}}} }
test_nonprod_single_allowed { count(deny) == 0 with input as {"kind":"Deployment", "metadata":{"labels":{}}, "spec":{"replicas":1, "template":{"spec":{"containers":[]}}}} }
test_latest_denied { count(deny) > 0 with input as {"kind":"Pod", "metadata":{}, "spec":{"securityContext":{"runAsNonRoot":true}, "containers":[{"name":"app", "image":"nginx:latest", "securityContext":{"allowPrivilegeEscalation":false, "readOnlyRootFilesystem":true}, "resources":{"requests":{"cpu":"1"}}}]}} }

