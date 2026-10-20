package infraguard.kubernetes

workload_kind {
	input.kind == "Deployment"
}

workload_kind {
	input.kind == "StatefulSet"
}

workload_kind {
	input.kind == "DaemonSet"
}

workload_kind {
	input.kind == "Job"
}

workload_kind {
	input.kind == "CronJob"
}

workload_kind {
	input.kind == "Pod"
}

pod_spec = spec {
	input.kind == "Pod"
	spec := input.spec
}

pod_spec = spec {
	input.kind == "CronJob"
	spec := input.spec.jobTemplate.spec.template.spec
}

pod_spec = spec {
	input.kind != "Pod"
	input.kind != "CronJob"
	spec := input.spec.template.spec
}

all_containers = containers {
	spec := pod_spec
	containers := array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", []))
}

message(id, msg, path) = encoded {
	encoded := json.marshal({"id": id, "msg": msg, "path": path, "resource": ""})
}
