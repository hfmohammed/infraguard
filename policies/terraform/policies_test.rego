package infraguard.terraform

empty := {"resource_changes": []}

ssh := {"resource_changes": [{"address": "aws_security_group.ssh", "type": "aws_security_group", "change": {"after": {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}}}]}

bucket := {"resource_changes": [{"address": "aws_s3_bucket.logs", "type": "aws_s3_bucket", "change": {"after": {"bucket": "logs"}}}]}

test_empty_allowed {
	count(deny) == 0 with input as empty
}

test_ssh_denied {
	count(deny) == 1 with input as ssh
}

test_world_ipv4 {
	world("0.0.0.0/0")
}

test_world_ipv6 {
	world("::/0")
}

test_private_not_world {
	not world("10.0.0.0/8")
}

test_bucket_missing_controls {
	count(deny) == 3 with input as bucket
}

test_public_access_block_missing {
	not public_access_blocked("logs") with input as bucket
}

test_public_access_block_complete {
	public_access_blocked("logs") with input as {"resource_changes": [{"type": "aws_s3_bucket_public_access_block", "change": {"after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}]}
}

test_no_encryption_empty {
	not encryption_exists("logs") with input as empty
}

test_no_versioning_empty {
	not versioning_exists("logs") with input as empty
}

test_message_has_resource {
	contains(tf_message("ID", "msg", "resource"), "resource")
}

test_changes_empty {
	count(changes) == 0 with input as empty
}

test_changes_ssh {
	count(changes) == 1 with input as ssh
}

test_ssh_address {
	changes[0].address == "aws_security_group.ssh" with input as ssh
}

test_bucket_address {
	changes[0].address == "aws_s3_bucket.logs" with input as bucket
}

test_bucket_type {
	changes[0].type == "aws_s3_bucket" with input as bucket
}

test_tf_message_json {
	contains(tf_message("A", "B", "C"), "\"id\":\"A\"")
}
