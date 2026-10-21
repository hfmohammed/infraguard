package infraguard.terraform

test_standalone_ipv6_ssh {
	"TF-AWS-NET-001" == policy_ids({"resource_changes": [{"address": "aws_security_group_rule.example", "type": "aws_security_group_rule", "change": {"after": {"type": "ingress", "protocol": "tcp", "from_port": 22, "to_port": 22, "ipv6_cidr_blocks": ["::/0"]}}}]})[_]
}

test_vpc_ipv6_ssh {
	"TF-AWS-NET-001" == policy_ids({"resource_changes": [{"address": "aws_vpc_security_group_ingress_rule.example", "type": "aws_vpc_security_group_ingress_rule", "change": {"after": {"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ipv6": "::/0"}}}]})[_]
}

test_tcp_all_ports {
	"TF-AWS-NET-002" == policy_ids({"resource_changes": [{"address": "aws_security_group_rule.example", "type": "aws_security_group_rule", "change": {"after": {"type": "ingress", "protocol": "tcp", "from_port": 0, "to_port": 65535, "cidr_blocks": ["0.0.0.0/0"]}}}]})[_]
}

test_inline_role_policy {
	"TF-AWS-IAM-001" == policy_ids({"resource_changes": [{"address": "aws_iam_role_policy.example", "type": "aws_iam_role_policy", "change": {"after": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}"}}}]})[_]
}

test_public_acl {
	"TF-AWS-S3-001" == policy_ids({"resource_changes": [{"address": "aws_s3_bucket_acl.example", "type": "aws_s3_bucket_acl", "change": {"after": {"acl": "public-read"}}}]})[_]
}

test_partial_access_block {
	"TF-AWS-S3-001" == policy_ids({"resource_changes": [{"address": "aws_s3_bucket_public_access_block.example", "type": "aws_s3_bucket_public_access_block", "change": {"after": {"block_public_acls": false}}}]})[_]
}

test_egress_is_not_ingress {
	not policy_ids({"resource_changes": [{"address": "aws_security_group_rule.egress", "type": "aws_security_group_rule", "change": {"after": {"type": "egress", "protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}}}]})["TF-AWS-NET-001"]
}
