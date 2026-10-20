package infraguard.terraform

deny[tf_message("TF-AWS-S3-001", "bucket does not block all public access", bucket.address)] {
	bucket := changes[_]
	bucket.type == "aws_s3_bucket"
	bucket.change.after != null
	not public_access_blocked(bucket.change.after.bucket)
	not public_access_reference(bucket)
}

public_access_blocked(name) {
	item := changes[_]
	item.type == "aws_s3_bucket_public_access_block"
	item.change.after.bucket == name
	item.change.after.block_public_acls
	item.change.after.block_public_policy
	item.change.after.ignore_public_acls
	item.change.after.restrict_public_buckets
}

deny[tf_message("TF-AWS-S3-002", "bucket has no encryption configuration", bucket.address)] {
	bucket := changes[_]
	bucket.type == "aws_s3_bucket"
	bucket.change.after != null
	not encryption_exists(bucket.change.after.bucket)
	not encryption_reference(bucket)
}

encryption_exists(name) {
	item := changes[_]
	item.type == "aws_s3_bucket_server_side_encryption_configuration"
	item.change.after.bucket == name
}

deny[tf_message("TF-AWS-S3-003", "bucket versioning is not enabled", bucket.address)] {
	bucket := changes[_]
	bucket.type == "aws_s3_bucket"
	bucket.change.after != null
	not versioning_exists(bucket.change.after.bucket)
	not versioning_reference(bucket)
}

versioning_exists(name) {
	item := changes[_]
	item.type == "aws_s3_bucket_versioning"
	item.change.after.bucket == name
	item.change.after.versioning_configuration[0].status == "Enabled"
}

# Planned IDs are often unknown until apply. Resolve their configuration references
# instead of treating a computed bucket ID as evidence that a control is absent.
references_bucket(item, bucket) {
	ref := item._references.bucket[_]
	ref == bucket.address
}

references_bucket(item, bucket) {
	ref := item._references.bucket[_]
	startswith(ref, concat("", [bucket.address, "."]))
}

public_access_reference(bucket) {
	item := changes[_]
	item.type == "aws_s3_bucket_public_access_block"
	item.change.after != null
	references_bucket(item, bucket)
	item.change.after.block_public_acls
	item.change.after.block_public_policy
	item.change.after.ignore_public_acls
	item.change.after.restrict_public_buckets
}

encryption_reference(bucket) {
	item := changes[_]
	item.type == "aws_s3_bucket_server_side_encryption_configuration"
	item.change.after != null
	references_bucket(item, bucket)
}

versioning_reference(bucket) {
	item := changes[_]
	item.type == "aws_s3_bucket_versioning"
	item.change.after != null
	references_bucket(item, bucket)
	item.change.after.versioning_configuration[0].status == "Enabled"
}
