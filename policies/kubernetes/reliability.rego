package infraguard.kubernetes

deny[message("K8S-REL-001", sprintf("container '%s' lacks resources", [container.name]), "resources")] {
	workload_kind
	container := all_containers[_]
	resources := object.get(container, "resources", {})
	not resource_guarantees(resources)
}

resource_guarantees(resources) {
	resources.requests.cpu
	resources.requests.memory
	resources.limits.memory
}

deny[message("K8S-REL-002", sprintf("container '%s' uses latest", [container.name]), "image")] {
	workload_kind
	container := all_containers[_]
	mutable_image(container.image)
}

mutable_image(image) {
	endswith(image, ":latest")
	not contains(image, "@sha256:")
}

mutable_image(image) {
	not contains(image, "@sha256:")
	last := array.reverse(split(image, "/"))[0]
	not contains(last, ":")
}

probe_workload {
	input.kind == "Deployment"
}

probe_workload {
	input.kind == "StatefulSet"
}

probe_workload {
	input.kind == "DaemonSet"
}

deny[message("K8S-REL-003", sprintf("container '%s' lacks health probes", [container.name]), "probes")] {
	probe_workload
	container := object.get(pod_spec, "containers", [])[_]
	not has_probes(container)
}

has_probes(container) {
	container.livenessProbe
	container.readinessProbe
}

deny[message("K8S-REL-004", "production deployment has fewer than two replicas", "spec.replicas")] {
	input.kind == "Deployment"
	object.get(object.get(input.metadata, "labels", {}), "infraguard.io/tier", "") == "prod"
	object.get(input.spec, "replicas", 1) < 2
}
