package infraguard.terraform

changes := object.get(input, "resource_changes", [])

tf_message(id, msg, resource) = encoded {
	encoded := json.marshal({"id": id, "msg": msg, "path": "change.after", "resource": resource})
}

world(cidr) {
	cidr == "0.0.0.0/0"
}

world(cidr) {
	cidr == "::/0"
}
