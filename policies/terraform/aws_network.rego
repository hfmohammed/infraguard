package infraguard.terraform

deny[tf_message("TF-AWS-NET-001", "SSH ingress is open to the world", change.address)] {
	change := changes[_]
	rule := ingress_rules(change)[_]
	ssh_port(rule)
	world_source(rule)
}

ssh_port(rule) {
	object.get(rule, "protocol", object.get(rule, "ip_protocol", "")) == "-1"
}

ssh_port(rule) {
	object.get(rule, "protocol", object.get(rule, "ip_protocol", "")) == "tcp"
	rule.from_port <= 22
	rule.to_port >= 22
}

deny[tf_message("TF-AWS-NET-002", "all ports are open to the world", change.address)] {
	change := changes[_]
	rule := ingress_rules(change)[_]
	all_ports(rule)
	world_source(rule)
}

ingress_rules(change) = rules {
	change.type == "aws_security_group"
	rules := object.get(change.change.after, "ingress", [])
}

ingress_rules(change) = [change.change.after] {
	change.type == "aws_security_group_rule"
	change.change.after.type == "ingress"
}

ingress_rules(change) = [change.change.after] {
	change.type == "aws_vpc_security_group_ingress_rule"
}

world_source(rule) {
	world(array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))[_])
}

world_source(rule) {
	world(rule.cidr_ipv4)
}

world_source(rule) {
	world(rule.cidr_ipv6)
}

all_ports(rule) {
	object.get(rule, "protocol", object.get(rule, "ip_protocol", "")) == "-1"
}

all_ports(rule) {
	rule.from_port == 0
	rule.to_port == 65535
}
