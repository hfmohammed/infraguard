package infraguard.kubernetes

deny[message("K8S-NET-001", "external service lacks approval", "spec.type")] {
	input.kind == "Service"
	input.spec.type == "NodePort"
	object.get(object.get(input.metadata, "annotations", {}), "infraguard.io/exposure-approved", "false") != "true"
}

deny[message("K8S-NET-001", "external service lacks approval", "spec.type")] {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	object.get(object.get(input.metadata, "annotations", {}), "infraguard.io/exposure-approved", "false") != "true"
}
