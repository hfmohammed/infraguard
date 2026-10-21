package infraguard.kubernetes

test_explicit_root_overrides_nonroot_flag {
	"K8S-SEC-002" == policy_ids({"kind": "Pod", "metadata": {}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1", "securityContext": {"runAsUser": 0}}]}})[_]
}

test_nonroot_user_with_nonroot_flag {
	not policy_ids({"kind": "Pod", "metadata": {}, "spec": {"securityContext": {"runAsNonRoot": true}, "containers": [{"name": "app", "image": "nginx:1", "securityContext": {"runAsUser": 101}}]}})["K8S-SEC-002"]
}
