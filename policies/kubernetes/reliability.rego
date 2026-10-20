package infraguard.kubernetes

deny[message("K8S-REL-001", sprintf("container '%s' lacks resources", [container.name]), "resources")] {
  workload_kind
  container := all_containers[_]
  resources := object.get(container, "resources", {})
  not object.get(object.get(resources, "requests", {}), "cpu", false)
}

deny[message("K8S-REL-002", sprintf("container '%s' uses latest", [container.name]), "image")] {
  workload_kind
  container := all_containers[_]
  endswith(container.image, ":latest")
  not contains(container.image, "@sha256:")
}

probe_workload { input.kind == "Deployment" }
probe_workload { input.kind == "StatefulSet" }
probe_workload { input.kind == "DaemonSet" }

deny[message("K8S-REL-003", sprintf("container '%s' lacks health probes", [container.name]), "probes")] {
  probe_workload
  container := object.get(pod_spec, "containers", [])[_]
  not container.livenessProbe
}

deny[message("K8S-REL-004", "production deployment has fewer than two replicas", "spec.replicas")] {
  input.kind == "Deployment"
  object.get(object.get(input.metadata, "labels", {}), "infraguard.io/tier", "") == "prod"
  object.get(input.spec, "replicas", 1) < 2
}

