package infraguard.terraform

deny[tf_message("TF-AWS-NET-001", "SSH ingress is open to the world", change.address)] {
  change := changes[_]
  change.type == "aws_security_group"
  rule := change.change.after.ingress[_]
  rule.from_port <= 22
  rule.to_port >= 22
  world(rule.cidr_blocks[_])
}

deny[tf_message("TF-AWS-NET-002", "all ports are open to the world", change.address)] {
  change := changes[_]
  change.type == "aws_security_group"
  rule := change.change.after.ingress[_]
  rule.protocol == "-1"
  world(array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))[_])
}

