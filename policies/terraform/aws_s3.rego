package infraguard.terraform

deny[tf_message("TF-AWS-S3-002", "bucket has no encryption configuration", bucket.address)] {
  bucket := changes[_]
  bucket.type == "aws_s3_bucket"
  not encryption_exists(bucket.change.after.bucket)
}

encryption_exists(name) {
  item := changes[_]
  item.type == "aws_s3_bucket_server_side_encryption_configuration"
  item.change.after.bucket == name
}

deny[tf_message("TF-AWS-S3-003", "bucket versioning is not enabled", bucket.address)] {
  bucket := changes[_]
  bucket.type == "aws_s3_bucket"
  not versioning_exists(bucket.change.after.bucket)
}

versioning_exists(name) {
  item := changes[_]
  item.type == "aws_s3_bucket_versioning"
  item.change.after.bucket == name
  item.change.after.versioning_configuration[0].status == "Enabled"
}

