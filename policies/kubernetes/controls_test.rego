package infraguard.kubernetes

policy_ids(document) = ids {
	ids := {json.unmarshal(item).id | item := deny[_]} with input as document
}

test_k8s_sec_001_rejects_violation {
	"K8S-SEC-001" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": true, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_sec_001_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-001"]
}

test_k8s_sec_002_rejects_violation {
	"K8S-SEC-002" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": false}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_sec_002_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-002"]
}

test_k8s_sec_003_rejects_violation {
	"K8S-SEC-003" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}], "hostNetwork": true}})[_]
}

test_k8s_sec_003_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-003"]
}

test_k8s_sec_004_rejects_violation {
	"K8S-SEC-004" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}], "volumes": [{"name": "host", "hostPath": {"path": "/"}}]}})[_]
}

test_k8s_sec_004_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-004"]
}

test_k8s_sec_005_rejects_violation {
	"K8S-SEC-005" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": true, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_sec_005_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-005"]
}

test_k8s_sec_006_rejects_violation {
	"K8S-SEC-006" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": {"add": ["SYS_ADMIN"]}}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_sec_006_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-006"]
}

test_k8s_sec_007_rejects_violation {
	"K8S-SEC-007" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": false}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_sec_007_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-SEC-007"]
}

test_k8s_rel_001_rejects_violation {
	"K8S-REL-001" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_rel_001_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-REL-001"]
}

test_k8s_rel_002_rejects_violation {
	"K8S-REL-002" == policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})[_]
}

test_k8s_rel_002_accepts_compliant {
	not policy_ids({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "safe"}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}}]}})["K8S-REL-002"]
}

test_k8s_rel_003_rejects_violation {
	"K8S-REL-003" == policy_ids({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "safe", "labels": {"infraguard.io/tier": "prod"}}, "spec": {"replicas": 2, "template": {"spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}, "livenessProbe": {"tcpSocket": {"port": 80}}}]}}}})[_]
}

test_k8s_rel_003_accepts_compliant {
	not policy_ids({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "safe", "labels": {"infraguard.io/tier": "prod"}}, "spec": {"replicas": 2, "template": {"spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}, "livenessProbe": {"tcpSocket": {"port": 80}}, "readinessProbe": {"tcpSocket": {"port": 80}}}]}}}})["K8S-REL-003"]
}

test_k8s_rel_004_rejects_violation {
	"K8S-REL-004" == policy_ids({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "safe", "labels": {"infraguard.io/tier": "prod"}}, "spec": {"replicas": 1, "template": {"spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}, "livenessProbe": {"tcpSocket": {"port": 80}}, "readinessProbe": {"tcpSocket": {"port": 80}}}]}}}})[_]
}

test_k8s_rel_004_accepts_compliant {
	not policy_ids({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "safe", "labels": {"infraguard.io/tier": "prod"}}, "spec": {"replicas": 2, "template": {"spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1.27.0", "securityContext": {"privileged": false, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}, "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "256Mi"}}, "livenessProbe": {"tcpSocket": {"port": 80}}, "readinessProbe": {"tcpSocket": {"port": 80}}}]}}}})["K8S-REL-004"]
}

test_k8s_net_001_rejects_violation {
	"K8S-NET-001" == policy_ids({"kind": "Service", "metadata": {}, "spec": {"type": "LoadBalancer"}})[_]
}

test_k8s_net_001_accepts_compliant {
	not policy_ids({"kind": "Service", "metadata": {}, "spec": {"type": "ClusterIP"}})["K8S-NET-001"]
}
