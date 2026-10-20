package infraguard.terraform

policy_ids(document) = ids {
	ids := {json.unmarshal(item).id | item := deny[_]} with input as document
}

test_tf_aws_s3_001_rejects_violation {
	"TF-AWS-S3-001" == policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "versioning_configuration": [{"status": "Enabled"}]}}}]})[_]
}

test_tf_aws_s3_001_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_public_access_block", "address": "aws_s3_bucket_public_access_block.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}, {"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "versioning_configuration": [{"status": "Enabled"}]}}}]})["TF-AWS-S3-001"]
}

test_tf_aws_s3_002_rejects_violation {
	"TF-AWS-S3-002" == policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_public_access_block", "address": "aws_s3_bucket_public_access_block.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}, {"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "versioning_configuration": [{"status": "Enabled"}]}}}]})[_]
}

test_tf_aws_s3_002_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_public_access_block", "address": "aws_s3_bucket_public_access_block.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}, {"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "versioning_configuration": [{"status": "Enabled"}]}}}]})["TF-AWS-S3-002"]
}

test_tf_aws_s3_003_rejects_violation {
	"TF-AWS-S3-003" == policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_public_access_block", "address": "aws_s3_bucket_public_access_block.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}, {"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}]})[_]
}

test_tf_aws_s3_003_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_s3_bucket", "address": "aws_s3_bucket.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_public_access_block", "address": "aws_s3_bucket_public_access_block.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}}}, {"type": "aws_s3_bucket_server_side_encryption_configuration", "address": "aws_s3_bucket_server_side_encryption_configuration.logs", "change": {"actions": ["create"], "after": {"bucket": "logs"}}}, {"type": "aws_s3_bucket_versioning", "address": "aws_s3_bucket_versioning.logs", "change": {"actions": ["create"], "after": {"bucket": "logs", "versioning_configuration": [{"status": "Enabled"}]}}}]})["TF-AWS-S3-003"]
}

test_tf_aws_net_001_rejects_violation {
	"TF-AWS-NET-001" == policy_ids({"resource_changes": [{"type": "aws_security_group", "address": "aws_security_group.test", "change": {"actions": ["create"], "after": {"ingress": [{"protocol": "tcp", "from_port": 20, "to_port": 25, "ipv6_cidr_blocks": ["::/0"]}]}}}]})[_]
}

test_tf_aws_net_001_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_security_group", "address": "aws_security_group.test", "change": {"actions": ["create"], "after": {"ingress": [{"protocol": "tcp", "from_port": 20, "to_port": 25, "ipv6_cidr_blocks": [], "cidr_blocks": ["10.0.0.0/8"]}]}}}]})["TF-AWS-NET-001"]
}

test_tf_aws_net_002_rejects_violation {
	"TF-AWS-NET-002" == policy_ids({"resource_changes": [{"type": "aws_security_group", "address": "aws_security_group.test", "change": {"actions": ["create"], "after": {"ingress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["0.0.0.0/0"]}]}}}]})[_]
}

test_tf_aws_net_002_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_security_group", "address": "aws_security_group.test", "change": {"actions": ["create"], "after": {"ingress": [{"protocol": "-1", "from_port": 0, "to_port": 0, "cidr_blocks": ["10.0.0.0/8"], "ipv6_cidr_blocks": []}]}}}]})["TF-AWS-NET-002"]
}

test_tf_aws_iam_001_rejects_violation {
	"TF-AWS-IAM-001" == policy_ids({"resource_changes": [{"type": "aws_iam_policy", "address": "aws_iam_policy.test", "change": {"actions": ["create"], "after": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"*\"],\"Resource\":[\"*\"]}]}"}}}]})[_]
}

test_tf_aws_iam_001_accepts_compliant {
	not policy_ids({"resource_changes": [{"type": "aws_iam_policy", "address": "aws_iam_policy.test", "change": {"actions": ["create"], "after": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::logs/*\"]}]}"}}}]})["TF-AWS-IAM-001"]
}
