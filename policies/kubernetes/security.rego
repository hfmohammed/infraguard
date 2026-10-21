package infraguard.kubernetes

deny[message("K8S-SEC-001", sprintf("container '%s' runs privileged", [container.name]), "securityContext.privileged")] {
	workload_kind
	container := all_containers[_]
	object.get(object.get(container, "securityContext", {}), "privileged", false)
}

deny[message("K8S-SEC-002", sprintf("container '%s' may run as root", [container.name]), "securityContext.runAsNonRoot")] {
	workload_kind
	container := all_containers[_]
	pod_security := object.get(pod_spec, "securityContext", {})
	security := object.get(container, "securityContext", {})
	not object.get(security, "runAsNonRoot", object.get(pod_security, "runAsNonRoot", false))
}

deny[message("K8S-SEC-003", "host namespace is enabled", "spec")] {
	workload_kind
	object.get(pod_spec, "hostNetwork", false)
}

deny[message("K8S-SEC-002", sprintf("container '%s' may run as root", [container.name]), "securityContext.runAsNonRoot")] {
	workload_kind
	container := all_containers[_]
	security := object.get(container, "securityContext", {})
	pod_security := object.get(pod_spec, "securityContext", {})
	object.get(security, "runAsUser", object.get(pod_security, "runAsUser", -1)) == 0
}

deny[message("K8S-SEC-003", "host namespace is enabled", "spec")] {
	workload_kind
	object.get(pod_spec, "hostPID", false)
}

deny[message("K8S-SEC-003", "host namespace is enabled", "spec")] {
	workload_kind
	object.get(pod_spec, "hostIPC", false)
}

deny[message("K8S-SEC-004", "workload uses hostPath", "spec.volumes")] {
	workload_kind
	volume := object.get(pod_spec, "volumes", [])[_]
	volume.hostPath
}

deny[message("K8S-SEC-005", sprintf("container '%s' allows privilege escalation", [container.name]), "securityContext.allowPrivilegeEscalation")] {
	workload_kind
	container := all_containers[_]
	object.get(object.get(container, "securityContext", {}), "allowPrivilegeEscalation", true)
}

dangerous_capability(capability) {
	capability == "SYS_ADMIN"
}

dangerous_capability(capability) {
	capability == "NET_ADMIN"
}

dangerous_capability(capability) {
	capability == "NET_RAW"
}

dangerous_capability(capability) {
	capability == "ALL"
}

deny[message("K8S-SEC-006", sprintf("container '%s' adds a dangerous capability", [container.name]), "securityContext.capabilities.add")] {
	workload_kind
	container := all_containers[_]
	capability := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "add", [])[_]
	dangerous_capability(capability)
}

deny[message("K8S-SEC-007", sprintf("container '%s' has a writable root filesystem", [container.name]), "securityContext.readOnlyRootFilesystem")] {
	workload_kind
	container := all_containers[_]
	not object.get(object.get(container, "securityContext", {}), "readOnlyRootFilesystem", false)
}
